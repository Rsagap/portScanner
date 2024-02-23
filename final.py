import os
import nmap
import threading
from tkinter import *
from tkinter import messagebox
from tkinter.ttk import Progressbar
from concurrent.futures import ThreadPoolExecutor

def is_host_up(url):
    response = os.system(f"ping -c 1 {url} > /dev/null 2>&1")
    return response == 0

def is_root():
    """Check if the script is running with root privileges."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Assuming Windows if os.geteuid() is not available
        return True  # In Windows, admin check is different and not handled here

def scan_segment(url, port_range, scan_type, output, progress, total_ports, lock, results_window):
    try:
        scanner = nmap.PortScanner()
        if scan_type == 'Quick Scan':
            arguments = '-T4'
        elif scan_type == 'Version Detection':
            arguments = '-sV'
        elif scan_type == 'OS Detection':
            if not is_root():
                raise PermissionError("OS Detection requires root privileges.")
            arguments = '-O'
        elif scan_type == 'Host Discovery':
            arguments = '-sn'
        else:
            arguments = ''

        scanner.scan(url, port_range, arguments=arguments)
        
        with lock:
            for host in scanner.all_hosts():
                output.insert(END, f'Host: {host} ({scanner[host].hostname()})\n')
                for proto in scanner[host].all_protocols():
                    lport = sorted(scanner[host][proto].keys())
                    for port in lport:
                        service_info = scanner[host][proto][port]
                        output.insert(END, f'Port: {port}/tcp, State: {service_info["state"]}\n')
                        if scan_type == 'Version Detection':
                            output.insert(END, f'Service: {service_info["name"]}, Version: {service_info["version"]}\n')
                        progress['value'] += (1 / total_ports) * 100
                        results_window.update_idletasks()
    except PermissionError as pe:
        with lock:
            output.insert(END, f'Error: {pe}\n')
    except Exception as e:
        with lock:
            output.insert(END, f'Error: {e}\n')

def start_scan(url, port_range, scan_type, output, progress, results_window):
    if not is_host_up(url):
        output.insert(END, f"Host {url} is not reachable. Please check the URL and try again.\n")
        return

    ports = port_range.split(',')
    total_ports = sum(map(lambda p: int(p.split('-')[1]) - int(p.split('-')[0]) + 1 if '-' in p else 1, ports))
    lock = threading.Lock()

    for segment in ports:
        threading.Thread(target=scan_segment, args=(url, segment, scan_type, output, progress, total_ports, lock, results_window)).start()

def create_window():
    window = Tk()
    window.title("Port Scanner")
    window.geometry('400x200')

    label_url = Label(window, text="URL:")
    label_url.grid(row=0, column=0)
    entry_url = Entry(window)
    entry_url.grid(row=0, column=1)

    label_port_range = Label(window, text="Port Range (e.g., 20-30,80,443):")
    label_port_range.grid(row=1, column=0)
    entry_port_range = Entry(window)
    entry_port_range.grid(row=1, column=1)

    scan_types = ['Quick Scan', 'Version Detection', 'OS Detection', 'Host Discovery']
    scan_type_var = StringVar(window)
    scan_type_var.set(scan_types[0])  # default value

    label_scan_type = Label(window, text="Scan Type:")
    label_scan_type.grid(row=2, column=0)
    scan_type_menu = OptionMenu(window, scan_type_var, *scan_types)
    scan_type_menu.grid(row=2, column=1)

    button_scan = Button(window, text="Start Scan", command=lambda: initiate_scan(entry_url.get(), entry_port_range.get(), scan_type_var.get(), window))
    button_scan.grid(row=3, column=1)

    window.mainloop()

def initiate_scan(url, port_range, scan_type, parent_window):
    if not url or not port_range:
        messagebox.showerror("Error", "Please enter a URL and port range.")
        return

    results_window = Toplevel(parent_window)
    results_window.title("Scan Results")
    results_window.geometry('400x500')

    output = Text(results_window, height=20)
    output.grid(row=1, column=0, columnspan=2)
    output.insert(END, "Scanning in progress...\n")

    progress = Progressbar(results_window, orient=HORIZONTAL, length=100, mode='determinate')
    progress.grid(row=0, column=0, columnspan=2)

    start_scan(url, port_range, scan_type, output, progress, results_window)

if __name__ == "__main__":
    create_window()
