import sys
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QComboBox, QLineEdit, QPushButton, 
                             QListWidget, QLabel, QListWidgetItem, QCheckBox)
from PyQt6.QtCore import Qt, pyqtSignal, QObject
from PyQt6.QtGui import QFont, QColor

class ScannerSignals(QObject):
    update_signal = pyqtSignal(str, str, str, str)
    progress_signal = pyqtSignal(int, int)

class IPScanner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IP-Scanner-Qt6")
        self.setGeometry(100, 100, 900, 600)
        
        self.scanning = False
        self.scanned_targets = 0
        self.total_targets = 0
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
        
        # Target input (IP range or Domain)
        target_type_layout = QHBoxLayout()
        target_type_layout.addWidget(QLabel("Target Type:"))
        self.target_type = QComboBox()
        self.target_type.addItems(["IP Range", "Domain"])
        self.target_type.currentTextChanged.connect(self.on_target_type_changed)
        target_type_layout.addWidget(self.target_type)
        layout.addLayout(target_type_layout)
        
        # IP range inputs
        self.ip_range_widget = QWidget()
        ip_range_layout = QHBoxLayout(self.ip_range_widget)
        ip_range_layout.addWidget(QLabel("Start IP:"))
        self.start_ip = QLineEdit("127.0.0.1")
        ip_range_layout.addWidget(self.start_ip)
        
        ip_range_layout.addWidget(QLabel("End IP:"))
        self.end_ip = QLineEdit("127.0.0.255")
        ip_range_layout.addWidget(self.end_ip)
        layout.addWidget(self.ip_range_widget)
        
        # Domain input
        self.domain_widget = QWidget()
        domain_layout = QHBoxLayout(self.domain_widget)
        domain_layout.addWidget(QLabel("Domain:"))
        self.domain_input = QLineEdit("example.com")
        domain_layout.addWidget(self.domain_input)
        layout.addWidget(self.domain_widget)
        self.domain_widget.hide()
        
        # Port range inputs
        port_range_layout = QHBoxLayout()
        port_range_layout.addWidget(QLabel("Start Port:"))
        self.start_port = QLineEdit("25565")
        port_range_layout.addWidget(self.start_port)
        
        port_range_layout.addWidget(QLabel("End Port:"))
        self.end_port = QLineEdit("25565")
        port_range_layout.addWidget(self.end_port)
        layout.addLayout(port_range_layout)
        
        # Single port checkbox
        self.single_port_checkbox = QCheckBox("Single port mode")
        self.single_port_checkbox.setChecked(True)
        self.single_port_checkbox.stateChanged.connect(self.on_single_port_changed)
        layout.addWidget(self.single_port_checkbox)
        
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
        
    def on_target_type_changed(self, text):
        if text == "IP Range":
            self.ip_range_widget.show()
            self.domain_widget.hide()
        else:
            self.ip_range_widget.hide()
            self.domain_widget.show()
    
    def on_single_port_changed(self, state):
        if state == Qt.CheckState.Checked.value:
            self.end_port.setEnabled(False)
            self.end_port.setText(self.start_port.text())
        else:
            self.end_port.setEnabled(True)
    
    def setup_list_header(self):
        header_item = QListWidgetItem()
        header_item.setText(f"{'Target':<20} {'Port':<8} {'Type':<12} {'Status':<10}")
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
    
    def resolve_domain(self, domain):
        """Resolve domain to IP addresses"""
        try:
            ips = socket.getaddrinfo(domain, None, socket.AF_INET)
            return list(set(ip[4][0] for ip in ips))
        except socket.gaierror:
            return []
        except Exception:
            return []
    
    def get_targets(self):
        """Get list of targets to scan based on selected type"""
        targets = []
        
        if self.target_type.currentText() == "IP Range":
            try:
                start = self.ip_to_int(self.start_ip.text())
                end = self.ip_to_int(self.end_ip.text())
                targets = [self.int_to_ip(ip_int) for ip_int in range(start, end + 1)]
            except:
                pass
        else:
            domain = self.domain_input.text().strip()
            if domain:
                targets = self.resolve_domain(domain)
        
        return targets
    
    def get_ports(self):
        """Get list of ports to scan"""
        try:
            start_port = int(self.start_port.text())
            if self.single_port_checkbox.isChecked():
                return [start_port]
            else:
                end_port = int(self.end_port.text())
                return list(range(start_port, end_port + 1))
        except:
            return []
    
    def scan_tcp(self, target, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            sock.close()
            return "Online" if result == 0 else "Offline"
        except:
            return "Unknown"
    
    def scan_udp(self, target, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(b'', (target, port))
            sock.recvfrom(1024)
            sock.close()
            return "Online"
        except socket.timeout:
            return "Offline"
        except:
            return "Unknown"
    
    def scan_minecraft(self, target, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, port))
            
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
    
    def scan_target(self, target, port, scan_type):
        if scan_type == "TCP":
            status = self.scan_tcp(target, port)
        elif scan_type == "UDP":
            status = self.scan_udp(target, port)
        elif scan_type == "TCP + UDP":
            tcp_status = self.scan_tcp(target, port)
            udp_status = self.scan_udp(target, port)
            status = f"TCP:{tcp_status}/UDP:{udp_status}"
        elif scan_type == "Minecraft":
            status = self.scan_minecraft(target, port)
        else:
            status = "Unknown"
        
        return target, port, scan_type, status
    
    def update_list(self, target, port, scan_type, status):
        item = QListWidgetItem()
        item.setText(f"{target:<20} {port:<8} {scan_type:<12} {status:<10}")
        
        if "Online" in status:
            item.setForeground(QColor(0, 128, 0))  # Green for online
        elif "Offline" in status:
            item.setForeground(QColor(255, 0, 0))  # Red for offline
        else:
            item.setForeground(QColor(128, 128, 128))  # Gray for unknown
            
        self.results_list.addItem(item)
        self.results_list.scrollToBottom()
    
    def update_progress(self, scanned, total):
        self.scanned_targets = scanned
        self.total_targets = total
        percentage = (scanned / total * 100) if total > 0 else 0
        self.progress_label.setText(f"Progress: {scanned}/{total} targets scanned ({percentage:.1f}%)")
    
    def scan_thread(self):
        try:
            targets = self.get_targets()
            ports = self.get_ports()
            scan_type = self.scan_type.currentText()
            
            if not targets:
                self.progress_label.setText("Error: No valid targets found")
                return
            
            if not ports:
                self.progress_label.setText("Error: No valid ports specified")
                return
            
            total_targets = len(targets) * len(ports)
            self.update_progress(0, total_targets)
            
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = []
                scanned = 0
                
                for target in targets:
                    if not self.scanning:
                        break
                        
                    for port in ports:
                        if not self.scanning:
                            break
                            
                        futures.append(executor.submit(self.scan_target, target, port, scan_type))
                
                for future in futures:
                    if not self.scanning:
                        break
                        
                    try:
                        target, port, scan_type, status = future.result(timeout=5)
                        self.signals.update_signal.emit(target, str(port), scan_type, status)
                        scanned += 1
                        self.signals.progress_signal.emit(scanned, total_targets)
                    except:
                        continue
            
            self.scanning = False
            self.scan_button.setEnabled(True)
            self.clear_scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.progress_label.setText("Scan completed" if scanned == total_targets else "Scan stopped")
            
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
            self.progress_label.setText("Starting scan...")
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
