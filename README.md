# NetExtract - Professional Forensic Suite 🔍

NetExtract is a lightweight, Python-based GUI tool designed for network forensics and packet analysis. Built using **Scapy** for packet manipulation and **Tkinter** for the interface, it allows security researchers and students to analyze PCAP files, extract artifacts, and detect suspicious patterns.

Unlike standard tools that rely solely on built-in arrays, this project implements a **Custom Linked List** data structure to manage packet memory efficiently during the session.

## 🚀 Key Features

* **Packet Analysis:** Parses `.pcap` and `.pcapng` files to display Source/Dest IPs, MAC addresses, Protocol, and TTL.
* **Artifact Extraction:**
    * **Credential Carving:** Automatically detects potential login attempts (User/Pass patterns) in unencrypted traffic.
    * **File Signature Detection:** Identifies magic bytes for EXE, PDF, ZIP, and PNG files transferred over the network.
* **Search & Filter:** Filter logs dynamically based on IP, Protocol, or payload content.
* **Custom Data Structures:** Implements a manual Forensic Linked List for log management.
* **Reporting:** Export analysis results to CSV for external reporting.

## 🛠️ Installation

### Prerequisites
* Python 3.x
* [Npcap](https://npcap.com/) (for Windows) or `libpcap` (for Linux/macOS)

### Dependencies
Install the required Python libraries:

```bash
pip install scapy
```
## 📸 Screenshots
<img width="1202" height="916" alt="image" src="https://github.com/user-attachments/assets/ac54e317-bbf2-48f8-8cb6-179c415e7623" />
