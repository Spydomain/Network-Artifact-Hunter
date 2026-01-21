import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading
import csv
import re
from datetime import datetime
from scapy.all import rdpcap, IP, TCP, UDP, Raw, Ether

# ==========================================
# 1. CUSTOM DATA STRUCTURE (Linked List)
# ==========================================
class ForensicNode:
    def __init__(self, p_num, ts, m_src, m_dst, i_src, i_dst, proto, ttl, info, decoded):
        self.p_num = p_num
        self.ts = ts
        self.m_src = m_src
        self.m_dst = m_dst
        self.i_src = i_src
        self.i_dst = i_dst
        self.proto = proto
        self.ttl = ttl
        self.info = info
        self.decoded = decoded
        self.next = None

class ForensicLinkedList:
    def __init__(self):
        self.head = None

    def insert(self, p_num, ts, m_src, m_dst, i_src, i_dst, proto, ttl, info, decoded):
        new_node = ForensicNode(p_num, ts, m_src, m_dst, i_src, i_dst, proto, ttl, info, decoded)
        if not self.head:
            self.head = new_node
        else:
            current = self.head
            while current.next:
                current = current.next
            current.next = new_node

# ==========================================
# 2. ENHANCED FORENSIC ENGINE
# ==========================================
class ForensicEngine:
    def __init__(self):
        self.log_data = ForensicLinkedList()
        # Real-world File Signatures & Attack Patterns
        self.file_sigs = {b"MZ": "EXE", b"%PDF": "PDF", b"PK\x03\x04": "ZIP", b"\x89PNG": "PNG"}
        self.creds_pattern = re.compile(r'(user|pass|login|pwd)=([^&;|\s]+)', re.IGNORECASE)

    def clear_session(self):
        """Logic to close the previous session and free memory"""
        self.log_data.head = None

    def analyze(self, file_path, callback):
        try:
            # Auto-reset session when a new file is imported
            self.clear_session()

            # Scapy rdpcap supports both .pcap and .pcapng
            packets = rdpcap(file_path)
            for i, pkt in enumerate(packets):
                if IP in pkt:
                    p_num = i + 1
                    ts = datetime.fromtimestamp(float(pkt.time)).strftime('%H:%M:%S.%f')

                    # Artifacts: MAC Addresses and TTL for OS Fingerprinting
                    m_src = pkt[Ether].src if Ether in pkt else "N/A"
                    m_dst = pkt[Ether].dst if Ether in pkt else "N/A"
                    i_src, i_dst = pkt[IP].src, pkt[IP].dst
                    proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
                    ttl = pkt[IP].ttl

                    status = "Normal Traffic"
                    decoded_text = "No Payload"

                    if pkt.haslayer(Raw):
                        raw = pkt[Raw].load
                        # Automatic Human-Readable Decoding
                        decoded_text = raw.decode('utf-8', errors='ignore').strip()

                        # Credential Carving
                        creds = self.creds_pattern.findall(decoded_text)
                        if creds:
                            status = f"🚩 LOGIN: {creds[0][0]}"

                        # File Signature Carving
                        for sig, name in self.file_sigs.items():
                            if raw.startswith(sig):
                                status = f"📂 FILE: {name}"

                    self.log_data.insert(p_num, ts, m_src, m_dst, i_src, i_dst, proto, ttl, status, decoded_text)
            callback("Forensic Session Updated Successfully.")
        except Exception as e:
            callback(f"Forensic Error: {str(e)}")

# ==========================================
# 3. GUI INTERFACE (Tkinter)
# ==========================================
class ForensicApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NetExtract - Professional Forensic Suite")
        self.root.geometry("1150x850")
        self.engine = ForensicEngine()

        # UI Header & Search Bar
        top = tk.Frame(root, bg="#2c3e50")
        top.pack(fill=tk.X)

        tk.Label(top, text="Search Artifacts:", bg="#2c3e50", fg="white").pack(side=tk.LEFT, padx=10, pady=15)
        self.search_entry = tk.Entry(top, width=35)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        # Search Button Logic Fix
        tk.Button(top, text="🔍 Filter Logs", command=self.apply_search).pack(side=tk.LEFT, padx=5)

        # Control Panel
        mid = tk.Frame(root)
        mid.pack(pady=10)
        tk.Button(mid, text="📁 Import PCAP/NG", command=self.load_pcap, bg="#e67e22", fg="white", width=20).grid(row=0, column=0, padx=5)
        tk.Button(mid, text="🗑️ Clear Display", command=self.manual_clear, bg="#c0392b", fg="white", width=20).grid(row=0, column=1, padx=5)
        tk.Button(mid, text="💾 Export CSV", command=self.export_report, bg="#2980b9", fg="white", width=20).grid(row=0, column=2, padx=5)

        # Output Terminal
        self.display = scrolledtext.ScrolledText(root, height=45, width=140, font=("Consolas", 10), bg="#000", fg="#00ff00")
        self.display.pack(pady=10, padx=10)

    def load_pcap(self):
        path = filedialog.askopenfilename(filetypes=[("Packet Captures", "*.pcap *.pcapng")])
        if path:
            # Clear old data immediately on new import
            self.display.delete(1.0, tk.END)
            self.display.insert(tk.END, f"[*] Closing old session... Analyzing: {path}\n")
            threading.Thread(target=self.engine.analyze, args=(path, self.on_complete)).start()

    def on_complete(self, msg):
        messagebox.showinfo("Status", msg)
        self.refresh_display()

    def manual_clear(self):
        """Clears both the UI and the custom Linked List"""
        self.engine.clear_session()
        self.display.delete(1.0, tk.END)
        messagebox.showinfo("Reset", "All session data cleared.")

    def apply_search(self):
        """Fixed Search Button Logic"""
        query = self.search_entry.get()
        self.refresh_display(query)

    def refresh_display(self, query=None):
        self.display.delete(1.0, tk.END)
        curr = self.engine.log_data.head
        while curr:
            block = f"PKT #{curr.p_num:<5} | Time: {curr.ts} | TTL: {curr.ttl}\n"
            block += f"MAC: {curr.m_src} -> {curr.m_dst}\n"
            block += f"IP:  {curr.i_src} -> {curr.i_dst} ({curr.proto})\n"
            block += f"EVENT: {curr.info}\n"
            block += f"DATA:  {curr.decoded[:250]}\n"
            block += "="*120 + "\n"

            # Search logic checks entire packet block for matching string
            if not query or query.lower() in block.lower():
                self.display.insert(tk.END, block)
            curr = curr.next

    def export_report(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv")
        if path:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["No", "Time", "MAC_S", "MAC_D", "IP_S", "IP_D", "Proto", "TTL", "Event", "Data"])
                curr = self.engine.log_data.head
                while curr:
                    writer.writerow([curr.p_num, curr.ts, curr.m_src, curr.m_dst, curr.i_src, curr.i_dst, curr.proto, curr.ttl, curr.info, curr.decoded])
                    curr = curr.next
            messagebox.showinfo("Export", "CSV Forensic Report generated.")

if __name__ == "__main__":
    root = tk.Tk()
    app = ForensicApp(root)
    root.mainloop()
