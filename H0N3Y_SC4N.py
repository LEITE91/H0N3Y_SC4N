from tkinter import *
from tkinter import messagebox
from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send
from scapy.all import sniff
import sys
import nmap
import datetime

def check_open_ports(host, port_range):
    open_ports = []

    # Create an Nmap PortScanner object
    scanner = nmap.PortScanner()

    # Scan for open ports on the specified host and port range
    scanner.scan(host, arguments=f"-p {port_range} -T4")

    # Iterate over the scan results
    for host in scanner.all_hosts():
        if scanner[host].state() == "up":
            for port in scanner[host]["tcp"]:
                if scanner[host]["tcp"][port]["state"] == "open":
                    open_ports.append(port)

    return open_ports

def handle_packet(packet):
    global open_ports, log_file

    if packet[TCP].flags == "S":
        # Get the current date and time for the logs
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Receive a TCP SYN packet (port scan)
        src_ip = packet[IP].dst
        dst_ip = packet[IP].src
        dst_port = packet[TCP].dport

        log_entry = f"[{current_time}] Received SYN packet from {src_ip} to {dst_ip}:{dst_port}\n"
        log_file.write(log_entry)
        log_file.flush()  # Forcing immediate write to the file
        print(f"Received SYN packet from {src_ip} to {dst_ip}:{dst_port}")
        sys.stdout.flush()  # Force immediate print display

        # Check if the port is open or closed
        if dst_port in open_ports:
            # Simulate closed port for open ports
            response_packet = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=packet[TCP].sport, flags="RA")
            send(response_packet, verbose=False)
            print(f"Sent RST/ACK response to {src_ip} for port {dst_port} (simulating closed port)")
            sys.stdout.flush()  # Force immediate print display
        else:
            # Simulate open port for closed ports
            response_packet = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=packet[TCP].sport, flags="SA")
            send(response_packet, verbose=False)
            print(f"Sent SYN/ACK response to {src_ip} for port {dst_port} (simulating open port)")
            sys.stdout.flush()  # Force immediate print display

def get_port_range():
    def get_ports():
        global open_ports, log_file

        port_range = port_entry.get()
        root.destroy()
        start_port, end_port = map(int, port_range.split("-"))
        open_ports = check_open_ports("localhost", f"{start_port}-{end_port}")

        # Create and open the log file
        log_file = open("_logs.txt", "a")

        print("Open ports on your host:", open_ports)
        sys.stdout.flush()  # Force immediate print display

        # Define a filter to capture only TCP SYN packets
        filter_string = "tcp[tcpflags] == tcp-syn"

        # Set the network interface to capture packets
        conf.iface = "Ethernet"  # Replace with your network interface

        # Start packet capture
        sniff(filter=filter_string, prn=handle_packet)

        log_file.close()

    root = Tk()
    root.title("Port Range")
    root.geometry("300x100")

    label = Label(root, text="Enter the port range (e.g., 1-6000):")
    label.pack()

    port_entry = Entry(root)
    port_entry.pack()

    button = Button(root, text="Scan Ports", command=get_ports)
    button.pack()

    root.mainloop()

if __name__ == "__main__":
    open_ports = []
    log_file = None
    get_port_range()