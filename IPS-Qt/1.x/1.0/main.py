import sys
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QComboBox, QLineEdit, QPushButton, 
                             QListWidget, QLabel, QListWidgetItem)
from PyQt6.QtCore import Qt, pyqtSignal, QObject
from PyQt6.QtGui import QFont, QColor

class ScannerSignals(QObject):
    update_signal = pyqtSignal(str, str, str, str)
    progress_signal = pyqtSignal(int, int)

class IPScanner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IP-Scanner-Qt6")
        self.setGeometry(100, 100, 800, 600)
        
        self.scanning = False
        self.scanned_ips = 0
        self.total_ips = 0
        self.signals = ScannerSignals()
        self.signals.update_signal.connect(self.update_list)
        self.signals.progress_signal.connect(self.update_progress)
        
        self.init_ui()
        
    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Scan type selection
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Scan Type:"))
        self.scan_type = QComboBox()
        self.scan_type.addItems(["TCP", "UDP", "TCP + UDP", "Minecraft"])
        type_layout.addWidget(self.scan_type)
        layout.addLayout(type_layout)
        
        # IP range inputs
        ip_range_layout = QHBoxLayout()
        ip_range_layout.addWidget(QLabel("Start IP:"))
        self.start_ip = QLineEdit("127.0.0.1")
        ip_range_layout.addWidget(self.start_ip)
        
        ip_range_layout.addWidget(QLabel("End IP:"))
        self.end_ip = QLineEdit("127.0.0.255")
        ip_range_layout.addWidget(self.end_ip)
        layout.addLayout(ip_range_layout)
        
        # Port input
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Port:"))
        self.port_input = QLineEdit("25565")
        port_layout.addWidget(self.port_input)
        layout.addLayout(port_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.scan_button = QPushButton("Scan")
        self.scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.scan_button)
        
        self.clear_scan_button = QPushButton("Clear + Scan")
        self.clear_scan_button.clicked.connect(self.clear_and_scan)
        button_layout.addWidget(self.clear_scan_button)
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        layout.addLayout(button_layout)
        
        # Progress label
        self.progress_label = QLabel("Ready to scan")
        layout.addWidget(self.progress_label)
        
        # Results list
        self.results_list = QListWidget()
        self.results_list.setFont(QFont("Courier", 10))
        self.setup_list_header()
        layout.addWidget(self.results_list)
        
    def setup_list_header(self):
        header_item = QListWidgetItem()
        header_item.setText(f"{'IP':<15} {'Port':<8} {'Type':<12} {'Status':<10}")
        header_item.setBackground(QColor(200, 200, 200))
        header_item.setFlags(Qt.ItemFlag.NoItemFlags)
        self.results_list.addItem(header_item)
        
    def ip_to_int(self, ip):
        return int(ip.split('.')[0]) * 256**3 + \
               int(ip.split('.')[1]) * 256**2 + \
               int(ip.split('.')[2]) * 256 + \
               int(ip.split('.')[3])
    
    def int_to_ip(self, num):
        return f"{num // 256**3 % 256}.{num // 256**2 % 256}.{num // 256 % 256}.{num % 256}"
    
    def get_ip_range(self):
        start = self.ip_to_int(self.start_ip.text())
        end = self.ip_to_int(self.end_ip.text())
        return start, end
    
    def scan_tcp(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return "Online" if result == 0 else "Offline"
        except:
            return "Unknown"
    
    def scan_udp(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(b'', (ip, port))
            sock.recvfrom(1024)
            sock.close()
            return "Online"
        except socket.timeout:
            return "Offline"
        except:
            return "Unknown"
    
    def scan_minecraft(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            
            # Minecraft handshake
            sock.send(b'\x10\x00\x00\x00\x00\x00\x00\x00\x00')
            data = sock.recv(1024)
            sock.close()
            
            if data and len(data) > 0:
                return "Online"
            else:
                return "Offline"
        except:
            return "Unknown"
    
    def scan_ip(self, ip, port, scan_type):
        if scan_type == "TCP":
            status = self.scan_tcp(ip, port)
        elif scan_type == "UDP":
            status = self.scan_udp(ip, port)
        elif scan_type == "TCP + UDP":
            tcp_status = self.scan_tcp(ip, port)
            udp_status = self.scan_udp(ip, port)
            status = f"TCP:{tcp_status}/UDP:{udp_status}"
        elif scan_type == "Minecraft":
            status = self.scan_minecraft(ip, port)
        else:
            status = "Unknown"
        
        return ip, port, scan_type, status
    
    def update_list(self, ip, port, scan_type, status):
        item = QListWidgetItem()
        item.setText(f"{ip:<15} {port:<8} {scan_type:<12} {status:<10}")
        
        if "Online" in status:
            item.setForeground(QColor(0, 128, 0))  # Green for online
        elif "Offline" in status:
            item.setForeground(QColor(255, 0, 0))  # Red for offline
        else:
            item.setForeground(QColor(128, 128, 128))  # Gray for unknown
            
        self.results_list.addItem(item)
        self.results_list.scrollToBottom()
    
    def update_progress(self, scanned, total):
        self.scanned_ips = scanned
        self.total_ips = total
        percentage = (scanned / total * 100) if total > 0 else 0
        self.progress_label.setText(f"Progress: {scanned}/{total} IPs scanned ({percentage:.1f}%)")
    
    def scan_thread(self):
        try:
            start_ip, end_ip = self.get_ip_range()
            port = int(self.port_input.text())
            scan_type = self.scan_type.currentText()
            
            total_ips = end_ip - start_ip + 1
            self.update_progress(0, total_ips)
            
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = []
                scanned = 0
                
                for ip_int in range(start_ip, end_ip + 1):
                    if not self.scanning:
                        break
                        
                    ip = self.int_to_ip(ip_int)
                    futures.append(executor.submit(self.scan_ip, ip, port, scan_type))
                
                for future in futures:
                    if not self.scanning:
                        break
                        
                    try:
                        ip, port, scan_type, status = future.result(timeout=5)
                        self.signals.update_signal.emit(ip, str(port), scan_type, status)
                        scanned += 1
                        self.signals.progress_signal.emit(scanned, total_ips)
                    except:
                        continue
            
            self.scanning = False
            self.scan_button.setEnabled(True)
            self.clear_scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.progress_label.setText("Scan completed" if self.scanning else "Scan stopped")
            
        except Exception as e:
            self.progress_label.setText(f"Error: {str(e)}")
            self.scanning = False
            self.scan_button.setEnabled(True)
            self.clear_scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
    
    def start_scan(self):
        if not self.scanning:
            self.scanning = True
            self.scan_button.setEnabled(False)
            self.clear_scan_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            threading.Thread(target=self.scan_thread, daemon=True).start()
    
    def clear_and_scan(self):
        self.results_list.clear()
        self.setup_list_header()
        self.start_scan()
    
    def stop_scan(self):
        self.scanning = False
        self.progress_label.setText("Stopping scan...")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    scanner = IPScanner()
    scanner.show()
    sys.exit(app.exec())
