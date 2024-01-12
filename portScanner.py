import nmap
from tkinter import *
from tkinter.ttk import Progressbar
import threading

def scan_segment(url, port_range, output, progress, total_ports, lock, results_window):
    try:
        scanner = nmap.PortScanner()
        # Fast scanning options
        scanner.scan(url, port_range, arguments='-T4')
        
        with lock:
            for host in scanner.all_hosts():
                for proto in scanner[host].all_protocols():
                    lport = scanner[host][proto].keys()
                    for port in lport:
                        output.insert(END, f'Host: {host}, Port: {port}, State: {scanner[host][proto][port]["state"]}\n')
                        progress['value'] += (1 / total_ports) * 100
                        results_window.update_idletasks()
    except Exception as e:
        with lock:
            output.insert(END, f'Error: {e}\n')

def start_scan(url, port_range):
    results_window = Toplevel(window)
    results_window.title("Scan Results")
    results_window.geometry('400x350')

    output = Text(results_window, height=10)
    output.grid(row=1, column=0, columnspan=2)
    output.insert(END, "Scanning in progress...\n")

    progress = Progressbar(results_window, orient=HORIZONTAL, length=100, mode='determinate')
    progress.grid(row=0, column=0, columnspan=2)

    if not url or not port_range:
        output.insert(END, "Please enter a URL and port range.\n")
        return

    # Split the port range into segments and scan each in a separate thread
    ports = port_range.split(',')
    total_ports = sum(map(lambda p: int(p.split('-')[1]) - int(p.split('-')[0]) + 1 if '-' in p else 1, ports))
    lock = threading.Lock()

    for segment in ports:
        threading.Thread(target=scan_segment, args=(url, segment, output, progress, total_ports, lock, results_window)).start()

def create_window():
    global window
    window = Tk()
    window.title("Port Scanner")
    window.geometry('300x100')

    label_url = Label(window, text="URL:")
    label_url.grid(row=0, column=0)
    entry_url = Entry(window)
    entry_url.grid(row=0, column=1)

    label_port_range = Label(window, text="Port Range (e.g., 20-30,80,443):")
    label_port_range.grid(row=1, column=0)
    entry_port_range = Entry(window)
    entry_port_range.grid(row=1, column=1)

    button_scan = Button(window, text="Start Scan", command=lambda: start_scan(entry_url.get(), entry_port_range.get()))
    button_scan.grid(row=2, column=1)

    window.mainloop()

if __name__ == "__main__":
    create_window()
