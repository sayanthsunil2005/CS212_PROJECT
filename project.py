import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog
from scapy.all import sniff, get_working_ifaces, IP, rdpcap, traceroute
from scapy.utils import wrpcap
from scapy.layers.inet import TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP  # Added ARP import
import networkx as nx
import matplotlib.pyplot as plt
import os

# GUI setup
root = tk.Tk()
root.title("Scapy Wireshark")
root.geometry("1250x600")

sniffing = False
sniff_thread = None
start_time = 0
captured_packets = []

selected_interface = tk.StringVar()
selected_filter = tk.StringVar()

# Get network interfaces
def get_interfaces():
    try:
        return [iface.name for iface in get_working_ifaces()]
    except Exception:
        return []

interfaces = get_interfaces()
if interfaces:
    selected_interface.set(interfaces[0])
else:
    interfaces = ["No interfaces found"]
    selected_interface.set(interfaces[0])

# Filter options (added ARP)
filter_options = ["All", "HTTP", "DNS", "TCP", "UDP", "ICMP", "ARP", "IP Address", "Destination Port"]
selected_filter.set("All")
filter_value = tk.StringVar()

def clean_summary(pkt):
    summary = pkt.summary()
    return summary.replace(" / Raw", "").replace(" / Padding", "")

def get_packet_type(pkt):
    if pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse):
        return "HTTP"
    elif pkt.haslayer(DNS):
        return "DNS"
    elif pkt.haslayer(ICMP):
        return "ICMP"
    elif pkt.haslayer(UDP):
        return "UDP"
    elif pkt.haslayer(TCP):
        return "TCP"
    elif pkt.haslayer(ARP):  # ARP support
        return "ARP"
    else:
        return "Other"

def get_ports(pkt):
    if TCP in pkt or UDP in pkt:
        return f"{pkt.sport} → {pkt.dport}"
    return ""

def packet_matches_filter(packet, selected):
    if selected == "All":
        return True
    elif selected == "HTTP":
        return packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse)
    elif selected == "DNS":
        return packet.haslayer(DNS)
    elif selected == "TCP":
        return packet.haslayer(TCP)
    elif selected == "UDP":
        return packet.haslayer(UDP)
    elif selected == "ICMP":
        return packet.haslayer(ICMP)
    elif selected == "ARP":  # ARP support
        return packet.haslayer(ARP)
    elif selected == "IP Address":
        ip_val = filter_value.get().strip()
        if not ip_val:
            return False
        return IP in packet and (packet[IP].src == ip_val or packet[IP].dst == ip_val)
    elif selected == "Destination Port":
        port_val = filter_value.get().strip()
        if not port_val.isdigit():
            return False
        port_val = int(port_val)
        return (TCP in packet and packet[TCP].dport == port_val) or \
               (UDP in packet and packet[UDP].dport == port_val)
    return False

def display_packets(packets):
    packet_list.delete(*packet_list.get_children())
    for packet in packets:
        arrival_time = packet.time - start_time
        src_ip = packet[IP].src if IP in packet else (packet[ARP].psrc if ARP in packet else "N/A")
        dst_ip = packet[IP].dst if IP in packet else (packet[ARP].pdst if ARP in packet else "N/A")
        pkt_type = get_packet_type(packet)
        info = f"{get_ports(packet)} {clean_summary(packet)}"
        tag = pkt_type if pkt_type in ["HTTP", "DNS", "TCP", "UDP", "ICMP", "ARP"] else "Other"
        packet_list.insert('', 'end', values=(f"{arrival_time:.3f}", src_ip, dst_ip, pkt_type, info), tags=(tag,))

def process_packet(packet):
    if not sniffing:
        return
    captured_packets.append(packet)
    try:
        arrival_time = packet.time - start_time
        src_ip = packet[IP].src if IP in packet else (packet[ARP].psrc if ARP in packet else "N/A")
        dst_ip = packet[IP].dst if IP in packet else (packet[ARP].pdst if ARP in packet else "N/A")
        pkt_type = get_packet_type(packet)
        info = f"{get_ports(packet)} {clean_summary(packet)}"
        tag = pkt_type if pkt_type in ["HTTP", "DNS", "TCP", "UDP", "ICMP", "ARP"] else "Other"
        packet_list.insert('', 'end', values=(f"{arrival_time:.3f}", src_ip, dst_ip, pkt_type, info), tags=(tag,))
        if len(packet_list.get_children()) > 200:
            packet_list.delete(packet_list.get_children()[0])
    except:
        pass

def start_sniffing():
    global sniffing, sniff_thread, start_time, captured_packets
    iface = selected_interface.get()
    if iface == "No interfaces found" or sniffing:
        return
    sniffing = True
    captured_packets = []
    packet_list.delete(*packet_list.get_children())
    start_time = time.time()
    sniff_thread = threading.Thread(
        target=lambda: sniff(
            iface=iface,
            prn=process_packet,
            store=False,
            stop_filter=lambda x: not sniffing
        ),
        daemon=True
    )
    sniff_thread.start()

def stop_sniffing():
    global sniffing
    sniffing = False

def apply_filter():
    filtered = [pkt for pkt in captured_packets if packet_matches_filter(pkt, selected_filter.get())]
    display_packets(filtered)

def save_packets():
    if not captured_packets:
        print("No packets to save.")
        return
    file_path = filedialog.asksaveasfilename(
        defaultextension=".pcap",
        filetypes=[("PCAP files", ".pcap"), ("All files", ".*")]
    )
    if file_path:
        wrpcap(file_path, captured_packets)
        print(f"Packets saved to {file_path}")

def load_pcap():
    global captured_packets, start_time
    file_path = filedialog.askopenfilename(filetypes=[("PCAP files", ".pcap"), ("All files", ".*")])
    if file_path:
        packets = rdpcap(file_path)
        captured_packets = packets
        start_time = packets[0].time if packets else time.time()
        display_packets(captured_packets)

def show_packet_route():
    def trace_and_plot(dst):
        try:
            route_status.config(text=f"Tracing route to {dst}...", fg="blue")
            ans, _ = traceroute(dst, maxttl=20, l4=ICMP(), verbose=0)
            hops = []
            for snd, rcv in ans:
                if rcv and rcv.src not in hops:
                    hops.append(rcv.src)
            if len(hops) <= 1:
                route_status.config(text="Route could not be fully determined. Only destination responded.", fg="orange")
            else:
                route_status.config(text=f"Route to {dst} traced with {len(hops)} hops.", fg="green")
            if hops:
                G = nx.DiGraph()
                for i in range(len(hops) - 1):
                    G.add_edge(hops[i], hops[i + 1])
                pos = nx.spring_layout(G)
                plt.figure(figsize=(10, 5))
                nx.draw(G, pos, with_labels=True, arrows=True,
                        node_color='lightblue', node_size=2000, font_size=9, edge_color='gray')
                plt.title(f"Traceroute to {dst} ({len(hops)} hops)")
                plt.tight_layout()
                plt.show()
                print("\nHops:")
                for i, hop in enumerate(hops, start=1):
                    print(f"{i}. {hop}")
            else:
                route_status.config(text="No ICMP replies received.", fg="red")
        except Exception as e:
            route_status.config(text=f"Traceroute failed: {e}", fg="red")

    selected = packet_list.selection()
    if not selected:
        route_status.config(text="No packet selected.", fg="red")
        return
    item = packet_list.item(selected[0])
    dst = item['values'][2]
    if dst == "N/A":
        route_status.config(text="Invalid destination IP.", fg="red")
        return
    threading.Thread(target=trace_and_plot, args=(dst,), daemon=True).start()

def show_detailed_info():
    selected = packet_list.selection()
    if not selected:
        route_status.config(text="No packet selected.", fg="red")
        return

    selected_time_str = packet_list.item(selected[0])['values'][0]
    try:
        selected_time = float(selected_time_str)
    except ValueError:
        route_status.config(text="Invalid selection.", fg="red")
        return

    pkt = None
    time_tolerance = 0.01

    for p in captured_packets:
        time_difference = abs(p.time - start_time - selected_time)
        if time_difference < time_tolerance:
            pkt = p
            break

    if not pkt:
        route_status.config(text="Packet not found.", fg="red")
        return

    detail_window = tk.Toplevel(root)
    detail_window.title("Packet Details")
    detail_window.geometry("800x600")

    text_area = tk.Text(detail_window, wrap=tk.WORD, font=("Courier", 10))

    lines = []
    lines.append(f"Frame Info:")
    lines.append(f"  - Packet Length: {len(pkt)} bytes")
    lines.append(f"  - Arrival Time: {pkt.time - start_time:.6f} s\n")

    for layer in pkt.layers():
        layer_instance = pkt.getlayer(layer)
        lines.append(f"{layer.name}:")
        if hasattr(layer_instance, "fields_desc"):
            for field in layer_instance.fields_desc:
                name = field.name
                value = layer_instance.getfieldval(name)
                lines.append(f"  - {name}: {value}")
        lines.append("")

    text_area.insert(tk.END, "\n".join(lines))
    text_area.config(state=tk.DISABLED)
    text_area.pack(fill=tk.BOTH, expand=True)

    route_status.config(text="Packet details displayed.", fg="green")

# GUI Layout
top_bar = tk.Frame(root)
top_bar.pack(anchor="w", padx=10, pady=5)
tk.Button(top_bar, text="Open file", command=load_pcap).pack(side=tk.LEFT)
tk.Button(top_bar, text="Save", command=save_packets).pack(side=tk.LEFT, padx=8)

iface_frame = tk.Frame(root)
iface_frame.pack(pady=5)
tk.Label(iface_frame, text="Select Interface: ").pack(side=tk.LEFT)
iface_dropdown = ttk.Combobox(iface_frame, textvariable=selected_interface, values=interfaces, state="readonly", width=50)
iface_dropdown.pack(side=tk.LEFT, padx=5)

filter_frame = tk.Frame(root)
filter_frame.pack(pady=5)
tk.Label(filter_frame, text="Select Filter: ").pack(side=tk.LEFT)
filter_dropdown = ttk.Combobox(filter_frame, textvariable=selected_filter, values=filter_options, state="readonly", width=20)
filter_dropdown.pack(side=tk.LEFT, padx=5)
filter_value_entry = tk.Entry(filter_frame, textvariable=filter_value, width=30)

def toggle_filter_entry(*args):
    if selected_filter.get() in ["IP Address", "Destination Port"]:
        filter_value_entry.pack(side=tk.LEFT, padx=5)
    else:
        filter_value_entry.pack_forget()

selected_filter.trace("w", toggle_filter_entry)
toggle_filter_entry()

btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)
tk.Button(btn_frame, text="Start Sniffing", command=start_sniffing).pack(side=tk.LEFT, padx=10)
tk.Button(btn_frame, text="Stop Sniffing", command=stop_sniffing).pack(side=tk.LEFT, padx=10)
tk.Button(btn_frame, text="Apply Filter", command=apply_filter).pack(side=tk.LEFT, padx=10)
tk.Button(btn_frame, text="Show Route", command=show_packet_route).pack(side=tk.LEFT, padx=10)
tk.Button(btn_frame, text="Show Packet Details", command=show_detailed_info).pack(side=tk.LEFT, padx=10)

route_status = tk.Label(root, text="", font=("Arial", 10))
route_status.pack(pady=5)

columns = ("Time (s)", "Source IP", "Destination IP", "Type", "Packet Info")
packet_list = ttk.Treeview(root, columns=columns, show="headings")
packet_list.column("Time (s)", width=80, anchor="center")
packet_list.column("Source IP", width=120)
packet_list.column("Destination IP", width=120)
packet_list.column("Type", width=80, anchor="center")
packet_list.column("Packet Info", width=850)
for col in columns:
    packet_list.heading(col, text=col)
packet_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Tag color styles (added ARP)
packet_list.tag_configure("HTTP", background="#d0f0c0")
packet_list.tag_configure("DNS", background="#fffacd")
packet_list.tag_configure("TCP", background="#e0ffff")
packet_list.tag_configure("UDP", background="#add8e6")
packet_list.tag_configure("ICMP", background="#ffb6c1")
packet_list.tag_configure("ARP", background="#f5deb3")  # ARP tag added
packet_list.tag_configure("Other", background="#ffffff")

def on_close():
    global sniffing, sniff_thread
    sniffing = False
    try:
        if sniff_thread and sniff_thread.is_alive():
            sniff_thread.join(timeout=2)
    except:
        pass
    root.destroy()
    os._exit(0)

root.protocol("WM_DELETE_WINDOW", on_close)
root.mainloop()