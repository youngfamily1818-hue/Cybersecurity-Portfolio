#!/usr/bin/env python3
"""Nmap Guardian: authorized network inventory and exposure assessment."""
import csv
import html
import ipaddress
import json
import queue
import shutil
import sqlite3
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

BASE = Path.home() / '.nmap_guardian'
BASE.mkdir(exist_ok=True)
DB = BASE / 'history.sqlite3'
MAX_HOSTS = 256
PROFILES = {
    'Host discovery': ['-sn'],
    'TCP ports (top 100)': ['-sT', '--top-ports', '100'],
    'Services (top 100)': ['-sT', '-sV', '--version-light', '--top-ports', '100'],
    'Safe security checks': ['-sT', '-sV', '--version-light', '--top-ports', '100', '--script', 'ssl-cert,ssl-enum-ciphers,http-security-headers,ssh2-enum-algos'],
}
RISK_PORTS = {21: ('HIGH', 'FTP can expose unencrypted credentials'), 23: ('HIGH', 'Telnet is unencrypted'), 445: ('MEDIUM', 'SMB exposed; verify access controls'), 3389: ('MEDIUM', 'RDP exposed; restrict access'), 5900: ('MEDIUM', 'VNC exposed; verify authentication'), 6379: ('HIGH', 'Redis exposed; verify binding and authentication'), 27017: ('HIGH', 'MongoDB exposed; verify binding and authentication'), 80: ('LOW', 'HTTP exposed; check HTTPS configuration')}
RANK = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}

def init_db():
    with sqlite3.connect(DB) as con:
        con.execute('CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, created TEXT, target TEXT, profile TEXT, result TEXT)')

def validate_target(value):
    value = value.strip()
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError('Use an IP address or CIDR network, not a hostname.') from exc
    if not (network.is_private or network.is_loopback or network.is_link_local):
        raise ValueError('Only private, loopback, or link-local IP ranges are permitted.')
    if network.num_addresses > MAX_HOSTS:
        raise ValueError(f'Limit each scan to {MAX_HOSTS} addresses or fewer.')
    return str(network)

def parse_xml(xml_data):
    root = ET.fromstring(xml_data)
    hosts = []
    for host in root.findall('host'):
        address = next((a.get('addr', '') for a in host.findall('address') if a.get('addrtype') == 'ipv4'), '')
        status = host.find('status')
        item = {'address': address, 'status': status.get('state', 'unknown') if status is not None else 'unknown', 'ports': [], 'findings': [], 'risk': 'INFO'}
        for port in host.findall('./ports/port'):
            state = port.find('state')
            if state is None or state.get('state') != 'open':
                continue
            number = int(port.get('portid', '0'))
            service = port.find('service')
            service_name = service.get('name', 'unknown') if service is not None else 'unknown'
            version = ' '.join(filter(None, [service.get('product', ''), service.get('version', '')])) if service is not None else ''
            item['ports'].append({'port': number, 'protocol': port.get('protocol', ''), 'service': service_name, 'version': version})
            if number in RISK_PORTS:
                level, description = RISK_PORTS[number]
                item['findings'].append({'severity': level, 'detail': f'Port {number}: {description}'})
            for script in port.findall('script'):
                script_id = script.get('id', '')
                output = script.get('output', '')[:2500]
                if output:
                    item['findings'].append({'severity': 'INFO', 'detail': f'NSE {script_id}: {output}'})
        for script in host.findall('./hostscript/script'):
            item['findings'].append({'severity': 'INFO', 'detail': f"NSE {script.get('id', '')}: {script.get('output', '')[:2500]}"})
        item['risk'] = max((f['severity'] for f in item['findings']), key=lambda x: RANK[x], default='INFO')
        hosts.append(item)
    return hosts

def export_report(record, path):
    path = Path(path)
    hosts = record['hosts']
    if path.suffix.lower() == '.json':
        path.write_text(json.dumps(record, indent=2), encoding='utf-8')
    elif path.suffix.lower() == '.csv':
        with path.open('w', newline='', encoding='utf-8') as handle:
            writer = csv.writer(handle)
            writer.writerow(['IP', 'Status', 'Risk', 'Port', 'Protocol', 'Service', 'Version', 'Findings'])
            for host in hosts:
                ports = host['ports'] or [{}]
                for port in ports:
                    writer.writerow([host['address'], host['status'], host['risk'], port.get('port', ''), port.get('protocol', ''), port.get('service', ''), port.get('version', ''), ' | '.join(f['detail'] for f in host['findings'])])
    elif path.suffix.lower() == '.html':
        esc = lambda x: html.escape(str(x))
        rows = []
        for host in hosts:
            for port in (host['ports'] or [{}]):
                rows.append('<tr>' + ''.join(f'<td>{esc(value)}</td>' for value in [host['address'], host['status'], host['risk'], port.get('port', ''), port.get('service', ''), port.get('version', '')]) + '</tr>')
        findings = ''.join(f"<li><b>{esc(h['address'])}</b>: {esc(f['severity'])} — <pre>{esc(f['detail'])}</pre></li>" for h in hosts for f in h['findings'])
        page = '<!doctype html><html><head><meta charset="utf-8"><title>Nmap Guardian Report</title><style>body{font:15px Arial;margin:36px;color:#17243a}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:9px;text-align:left}th{background:#e7efff}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style></head><body>'
        page += f'<h1>Nmap Guardian</h1><p>Target: {esc(record["target"])} | Profile: {esc(record["profile"])} | Date: {esc(record["created"])}</p><h2>Hosts and ports</h2><table><tr><th>IP</th><th>Status</th><th>Risk</th><th>Port</th><th>Service</th><th>Version</th></tr>{"".join(rows)}</table><h2>Observations</h2><ul>{findings}</ul><p>Risk labels are exposure heuristics, not confirmed vulnerabilities.</p></body></html>'
        path.write_text(page, encoding='utf-8')
    else:
        raise ValueError('Unsupported report format')

class App:
    def __init__(self, root):
        self.root = root
        self.root.title('Nmap Guardian | Authorized Network Scanner')
        self.root.geometry('1060x720')
        self.events = queue.Queue()
        self.process = None
        self.record = None
        self.busy = False
        self.build()
        self.load_history()
        self.root.after(100, self.poll)

    def build(self):
        shell = ttk.Frame(self.root, padding=14)
        shell.pack(fill='both', expand=True)
        ttk.Label(shell, text='NMAP GUARDIAN', font=('Arial', 20, 'bold')).pack(anchor='w')
        ttk.Label(shell, text='Private-network discovery • Service inventory • Non-exploitative security checks').pack(anchor='w', pady=(0, 12))
        settings = ttk.LabelFrame(shell, text='Scan configuration', padding=12)
        settings.pack(fill='x')
        ttk.Label(settings, text='IP / CIDR').grid(row=0, column=0, sticky='w')
        self.target = tk.StringVar(value='192.168.1.0/24')
        ttk.Entry(settings, textvariable=self.target, width=27).grid(row=0, column=1, padx=8)
        ttk.Label(settings, text='Profile').grid(row=0, column=2)
        self.profile = tk.StringVar(value='Host discovery')
        ttk.Combobox(settings, textvariable=self.profile, values=list(PROFILES), state='readonly', width=25).grid(row=0, column=3, padx=8)
        self.start_btn = ttk.Button(settings, text='Start scan', command=self.start)
        self.start_btn.grid(row=0, column=4, padx=5)
        self.stop_btn = ttk.Button(settings, text='Stop', command=self.stop, state='disabled')
        self.stop_btn.grid(row=0, column=5)
        self.authorized = tk.BooleanVar(value=False)
        ttk.Checkbutton(settings, text='I own this network or have explicit authorization to scan it.', variable=self.authorized).grid(row=1, column=0, columnspan=6, sticky='w', pady=(10, 0))
        self.status = tk.StringVar(value='Ready. Nmap must be installed and available in PATH.')
        ttk.Label(shell, textvariable=self.status).pack(anchor='w', pady=8)
        notebook = ttk.Notebook(shell)
        notebook.pack(fill='both', expand=True)
        result_tab = ttk.Frame(notebook, padding=8)
        history_tab = ttk.Frame(notebook, padding=8)
        notebook.add(result_tab, text='Scan results')
        notebook.add(history_tab, text='History')
        cols = ('IP', 'Status', 'Risk', 'Port', 'Service', 'Version')
        self.table = ttk.Treeview(result_tab, columns=cols, show='headings', height=12)
        for col in cols:
            self.table.heading(col, text=col)
            self.table.column(col, width=110 if col != 'Version' else 250)
        self.table.pack(fill='both', expand=True)
        ttk.Label(result_tab, text='Observations (risk labels indicate exposure, not verified CVEs)').pack(anchor='w', pady=(8, 2))
        self.details = tk.Text(result_tab, height=9, wrap='word')
        self.details.pack(fill='both', expand=True)
        ttk.Button(result_tab, text='Export report…', command=self.export).pack(anchor='e', pady=8)
        self.history = ttk.Treeview(history_tab, columns=('ID', 'Date', 'Target', 'Profile'), show='headings')
        for col, width in [('ID', 240), ('Date', 200), ('Target', 180), ('Profile', 220)]:
            self.history.heading(col, text=col)
            self.history.column(col, width=width)
        self.history.pack(fill='both', expand=True)
        ttk.Button(history_tab, text='Load selected scan', command=self.open_history).pack(anchor='e', pady=8)

    def start(self):
        if self.busy:
            return
        if not self.authorized.get():
            messagebox.showerror('Authorization required', 'Confirm you have authorization before scanning.')
            return
        try:
            target = validate_target(self.target.get())
        except ValueError as exc:
            messagebox.showerror('Invalid scope', str(exc))
            return
        nmap = shutil.which('nmap')
        if not nmap:
            messagebox.showerror('Nmap missing', 'Install Nmap and ensure nmap is on your PATH.')
            return
        profile = self.profile.get()
        self.busy = True
        self.start_btn.configure(state='disabled')
        self.stop_btn.configure(state='normal')
        self.status.set(f'Scanning {target} using {profile}…')
        threading.Thread(target=self.worker, args=(nmap, target, profile), daemon=True).start()

    def worker(self, nmap, target, profile):
        try:
            cmd = [nmap, *PROFILES[profile], '-n', '--max-retries', '1', '--host-timeout', '120s', '-oX', '-', target]
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = self.process.communicate(timeout=900)
            if self.process.returncode != 0:
                raise RuntimeError(stderr.decode(errors='replace')[:1200] or 'Nmap failed')
            hosts = parse_xml(stdout)
            record = {'id': str(uuid.uuid4()), 'created': datetime.now(timezone.utc).isoformat(timespec='seconds'), 'target': target, 'profile': profile, 'hosts': hosts}
            with sqlite3.connect(DB) as con:
                con.execute('INSERT INTO scans VALUES (?,?,?,?,?)', (record['id'], record['created'], target, profile, json.dumps(record)))
            self.events.put(('success', record))
        except subprocess.TimeoutExpired:
            if self.process:
                self.process.kill()
                self.process.communicate()
            self.events.put(('error', 'Scan exceeded the 15-minute limit.'))
        except Exception as exc:
            self.events.put(('error', str(exc)))
        finally:
            self.process = None
            self.events.put(('done', None))

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.kill()
            self.status.set('Stopping scan…')

    def poll(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == 'success':
                    self.show_record(payload)
                    self.load_history()
                    self.status.set(f'Completed: {len(payload["hosts"])} responding host record(s).')
                elif kind == 'error':
                    self.status.set('Scan failed or stopped.')
                    messagebox.showerror('Scan error', payload)
                elif kind == 'done':
                    self.busy = False
                    self.start_btn.configure(state='normal')
                    self.stop_btn.configure(state='disabled')
        except queue.Empty:
            pass
        self.root.after(100, self.poll)

    def show_record(self, record):
        self.record = record
        self.table.delete(*self.table.get_children())
        self.details.delete('1.0', 'end')
        for host in record['hosts']:
            for port in (host['ports'] or [{}]):
                self.table.insert('', 'end', values=(host['address'], host['status'], host['risk'], port.get('port', ''), port.get('service', ''), port.get('version', '')))
            for finding in host['findings']:
                self.details.insert('end', f"[{host['address']}] {finding['severity']}: {finding['detail']}\n\n")
        if not record['hosts']:
            self.details.insert('end', 'No responding hosts were reported. Check connectivity, firewall rules, and authorization scope.')

    def load_history(self):
        self.history.delete(*self.history.get_children())
        with sqlite3.connect(DB) as con:
            for row in con.execute('SELECT id,created,target,profile FROM scans ORDER BY created DESC LIMIT 200'):
                self.history.insert('', 'end', values=row)

    def open_history(self):
        selection = self.history.selection()
        if not selection:
            return
        scan_id = self.history.item(selection[0], 'values')[0]
        with sqlite3.connect(DB) as con:
            row = con.execute('SELECT result FROM scans WHERE id=?', (scan_id,)).fetchone()
        if row:
            self.show_record(json.loads(row[0]))
            self.status.set('Loaded historical scan.')

    def export(self):
        if not self.record:
            messagebox.showinfo('No results', 'Run or load a scan first.')
            return
        path = filedialog.asksaveasfilename(defaultextension='.html', filetypes=[('HTML', '*.html'), ('CSV', '*.csv'), ('JSON', '*.json')])
        if path:
            try:
                export_report(self.record, path)
                messagebox.showinfo('Report saved', f'Saved to {path}')
            except Exception as exc:
                messagebox.showerror('Export failed', str(exc))

if __name__ == '__main__':
    init_db()
    root = tk.Tk()
    App(root)
    root.mainloop()
