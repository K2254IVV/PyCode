import sys
import socket
import threading
import time
import csv
from concurrent.futures import ThreadPoolExecutor
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QComboBox, QLineEdit, QPushButton, 
                             QListWidget, QLabel, QListWidgetItem, QCheckBox,
                             QGroupBox, QToolButton, QSpinBox, QMenu, 
                             QFileDialog, QInputDialog)
from PyQt6.QtCore import Qt, pyqtSignal, QObject
from PyQt6.QtGui import QFont, QColor, QIcon, QAction

class ScannerSignals(QObject):
    update_signal = pyqtSignal(str, str, str, str)
    progress_signal = pyqtSignal(int, int)

class IPScanner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IP-Scanner-Qt6")
        self.setGeometry(100, 100, 1000, 800)
        
        self.scanning = False
        self.scanned_targets = 0
        self.total_targets = 0
        self.signals = ScannerSignals()
        self.signals.update_signal.connect(self.update_list)
        self.signals.progress_signal.connect(self.update_progress)
        
        self.sort_order = Qt.SortOrder.AscendingOrder
        self.current_sort_field = None
        
        self.init_ui()
        
    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Top panel with buttons
        top_panel = QHBoxLayout()
        
        self.settings_button = QPushButton("Settings")
        self.settings_button.setCheckable(True)
        self.settings_button.setChecked(True)
        self.settings_button.clicked.connect(self.toggle_settings)
        top_panel.addWidget(self.settings_button)
        
        self.sort_button = QPushButton("Sort")
        self.sort_button.setCheckable(True)
        self.sort_button.setChecked(False)
        self.sort_button.clicked.connect(self.toggle_sort_panel)
        top_panel.addWidget(self.sort_button)
        
        self.scan_button = QPushButton("Scan")
        self.scan_button.clicked.connect(self.start_scan)
        top_panel.addWidget(self.scan_button)
        
        self.clear_scan_button = QPushButton("Clear + Scan")
        self.clear_scan_button.clicked.connect(self.clear_and_scan)
        top_panel.addWidget(self.clear_scan_button)
        
        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear_results)
        top_panel.addWidget(self.clear_button)
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        top_panel.addWidget(self.stop_button)
        
        layout.addLayout(top_panel)
        
        # Settings groupbox (collapsible)
        self.settings_group = QGroupBox()
        self.settings_group.setVisible(True)
        settings_layout = QVBoxLayout(self.settings_group)
        
        # Scan type
        scan_type_layout = QHBoxLayout()
        scan_type_layout.addWidget(QLabel("Scan Type:"))
        self.scan_type = QComboBox()
        self.scan_type.addItems(["TCP", "UDP", "TCP + UDP", "Minecraft"])
        scan_type_layout.addWidget(self.scan_type)
        settings_layout.addLayout(scan_type_layout)
        
        # Target type
        target_type_layout = QHBoxLayout()
        target_type_layout.addWidget(QLabel("Target Type:"))
        self.target_type = QComboBox()
        self.target_type.addItems(["Single IP", "IP Range", "Domain"])
        self.target_type.currentTextChanged.connect(self.on_target_type_changed)
        target_type_layout.addWidget(self.target_type)
        settings_layout.addLayout(target_type_layout)
        
        # Target inputs
        self.target_widgets = {
            "Single IP": self.create_single_ip_widget(),
            "IP Range": self.create_ip_range_widget(),
            "Domain": self.create_domain_widget()
        }
        
        for widget in self.target_widgets.values():
            settings_layout.addWidget(widget)
        
        # Show only current target widget
        self.on_target_type_changed(self.target_type.currentText())
        
        # Port settings
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Port Mode:"))
        self.port_mode = QComboBox()
        self.port_mode.addItems(["Single Port", "Port Range"])
        self.port_mode.currentTextChanged.connect(self.on_port_mode_changed)
        port_layout.addWidget(self.port_mode)
        settings_layout.addLayout(port_layout)
        
        # Port inputs
        port_inputs_layout = QHBoxLayout()
        port_inputs_layout.addWidget(QLabel("Start Port:"))
        self.start_port = QSpinBox()
        self.start_port.setRange(1, 65535)
        self.start_port.setValue(25565)
        port_inputs_layout.addWidget(self.start_port)
        
        port_inputs_layout.addWidget(QLabel("End Port:"))
        self.end_port = QSpinBox()
        self.end_port.setRange(1, 65535)
        self.end_port.setValue(25565)
        self.end_port.setEnabled(False)
        port_inputs_layout.addWidget(self.end_port)
        settings_layout.addLayout(port_inputs_layout)
        
        # Advanced settings
        advanced_group = QGroupBox("Advanced")
        advanced_layout = QVBoxLayout(advanced_group)
        
        delay_layout = QHBoxLayout()
        delay_layout.addWidget(QLabel("Delay (ms):"))
        self.delay_spinbox = QSpinBox()
        self.delay_spinbox.setRange(0, 5000)
        self.delay_spinbox.setValue(0)
        self.delay_spinbox.setSuffix(" ms")
        delay_layout.addWidget(self.delay_spinbox)
        delay_layout.addStretch()
        advanced_layout.addLayout(delay_layout)
        
        settings_layout.addWidget(advanced_group)
        layout.addWidget(self.settings_group)
        
        # Sort panel (collapsible)
        self.sort_group = QGroupBox()
        self.sort_group.setVisible(False)
        sort_layout = QVBoxLayout(self.sort_group)
        
        # Sort options
        sort_options_layout = QHBoxLayout()
        sort_options_layout.addWidget(QLabel("Sort by:"))
        
        # Status sort (toggle button)
        self.sort_status_btn = QPushButton("Status: Online")
        self.sort_status_btn.setCheckable(True)
        self.sort_status_btn.clicked.connect(self.toggle_status_sort)
        sort_options_layout.addWidget(self.sort_status_btn)
        
        # IP sort fields
        ip_sort_layout = QHBoxLayout()
        ip_sort_layout.addWidget(QLabel("IP:"))
        self.ip_sort_field = QLineEdit()
        self.ip_sort_field.setPlaceholderText("Enter IP to filter")
        self.ip_sort_btn = QPushButton("Sort IP")
        self.ip_sort_btn.clicked.connect(self.sort_by_ip)
        ip_sort_layout.addWidget(self.ip_sort_field)
        ip_sort_layout.addWidget(self.ip_sort_btn)
        sort_options_layout.addLayout(ip_sort_layout)
        
        # Port sort fields
        port_sort_layout = QHBoxLayout()
        port_sort_layout.addWidget(QLabel("Port:"))
        self.port_sort_field = QSpinBox()
        self.port_sort_field.setRange(1, 65535)
        self.port_sort_field.setValue(25565)
        self.port_sort_btn = QPushButton("Sort Port")
        self.port_sort_btn.clicked.connect(self.sort_by_port)
        port_sort_layout.addWidget(self.port_sort_field)
        port_sort_layout.addWidget(self.port_sort_btn)
        sort_options_layout.addLayout(port_sort_layout)
        
        sort_layout.addLayout(sort_options_layout)
        
        # Save sorting button
        self.save_sort_btn = QPushButton("Save Sorting File")
        self.save_sort_btn.clicked.connect(self.save_sorted_results)
        sort_layout.addWidget(self.save_sort_btn)
        
        layout.addWidget(self.sort_group)
        
        # Progress label
        self.progress_label = QLabel("Ready to scan")
        layout.addWidget(self.progress_label)
        
        # Results list with context menu
        self.results_list = QListWidget()
        self.results_list.setFont(QFont("Courier", 10))
        self.results_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.results_list.customContextMenuRequested.connect(self.show_context_menu)
        self.setup_list_header()
        layout.addWidget(self.results_list)
        
    def create_single_ip_widget(self):
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.addWidget(QLabel("IP Address:"))
        self.single_ip = QLineEdit("127.0.0.1")
        layout.addWidget(self.single_ip)
        return widget
        
    def create_ip_range_widget(self):
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.addWidget(QLabel("Start IP:"))
        self.start_ip = QLineEdit("127.0.0.1")
        layout.addWidget(self.start_ip)
        layout.addWidget(QLabel("End IP:"))
        self.end_ip = QLineEdit("127.0.0.255")
        layout.addWidget(self.end_ip)
        return widget
        
    def create_domain_widget(self):
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.addWidget(QLabel("Domain:"))
        self.domain_input = QLineEdit("example.com")
        layout.addWidget(self.domain_input)
        return widget
        
    def toggle_settings(self):
        self.settings_group.setVisible(self.settings_button.isChecked())
        
    def toggle_sort_panel(self):
        self.sort_group.setVisible(self.sort_button.isChecked())
        
    def on_target_type_changed(self, text):
        for key, widget in self.target_widgets.items():
            widget.setVisible(key == text)
            
    def on_port_mode_changed(self, text):
        self.end_port.setEnabled(text == "Port Range")
        
    def setup_list_header(self):
        header_item = QListWidgetItem()
        header_item.setText(f"{'Target':<20} {'Port':<8} {'Type':<12} {'Status':<10}")
        header_item.setBackground(QColor(200, 200, 200))
        header_item.setFlags(Qt.ItemFlag.NoItemFlags)
        self.results_list.addItem(header_item)
    
    def show_context_menu(self, position):
        context_menu = QMenu(self)
        
        # Sort submenu
        sort_menu = context_menu.addMenu("Sort by")
        
        sort_status_action = QAction("Toggle Status Filter", self)
        sort_status_action.triggered.connect(self.toggle_status_sort)
        sort_menu.addAction(sort_status_action)
        
        sort_ip_action = QAction("Sort by IP", self)
        sort_ip_action.triggered.connect(self.sort_by_ip)
        sort_menu.addAction(sort_ip_action)
        
        sort_port_action = QAction("Sort by Port", self)
        sort_port_action.triggered.connect(self.sort_by_port)
        sort_menu.addAction(sort_port_action)
        
        # Copy action
        copy_action = QAction("Copy Data", self)
        copy_action.triggered.connect(self.copy_selected_data)
        context_menu.addAction(copy_action)
        
        context_menu.exec(self.results_list.mapToGlobal(position))
    
    def copy_selected_data(self):
        selected_items = self.results_list.selectedItems()
        if selected_items:
            text = selected_items[0].text()
            QApplication.clipboard().setText(text)
    
    def toggle_status_sort(self):
        if self.sort_status_btn.isChecked():
            self.sort_status_btn.setText("Status: Offline")
            self.filter_by_status("Offline")
        else:
            self.sort_status_btn.setText("Status: Online")
            self.filter_by_status("Online")
    
    def filter_by_status(self, status_filter):
        # Show only items with specified status
        for i in range(1, self.results_list.count()):
            item = self.results_list.item(i)
            item_text = item.text()
            current_status = item_text.split()[-1] if len(item_text.split()) >= 4 else ""
            
            if status_filter.lower() in current_status.lower():
                item.setHidden(False)
            else:
                item.setHidden(True)
    
    def sort_by_ip(self):
        target_ip = self.ip_sort_field.text().strip()
        if not target_ip:
            # Sort all IPs numerically
            items = []
            for i in range(1, self.results_list.count()):
                item = self.results_list.item(i)
                items.append((item, self.ip_to_int(item.text().split()[0])))
            
            items.sort(key=lambda x: x[1], reverse=self.sort_order == Qt.SortOrder.DescendingOrder)
            
            # Recreate list with sorted items
            self.recreate_sorted_list([item[0] for item in items])
        else:
            # Filter by specific IP
            for i in range(1, self.results_list.count()):
                item = self.results_list.item(i)
                item_text = item.text()
                current_ip = item_text.split()[0] if len(item_text.split()) >= 1 else ""
                
                if target_ip.lower() in current_ip.lower():
                    item.setHidden(False)
                else:
                    item.setHidden(True)
    
    def sort_by_port(self):
        target_port = self.port_sort_field.value()
        
        # Filter by specific port
        for i in range(1, self.results_list.count()):
            item = self.results_list.item(i)
            item_text = item.text()
            if len(item_text.split()) >= 2:
                try:
                    current_port = int(item_text.split()[1])
                    if current_port == target_port:
                        item.setHidden(False)
                    else:
                        item.setHidden(True)
                except ValueError:
                    item.setHidden(True)
    
    def recreate_sorted_list(self, sorted_items):
        # Save current scroll position and selection
        scroll_position = self.results_list.verticalScrollBar().value()
        
        # Clear and rebuild list
        self.results_list.clear()
        self.setup_list_header()
        
        for item in sorted_items:
            # Create new item with same text
            new_item = QListWidgetItem(item.text())
            new_item.setForeground(item.foreground())
            self.results_list.addItem(new_item)
        
        # Restore scroll position
        self.results_list.verticalScrollBar().setValue(scroll_position)
    
    def save_sorted_results(self):
        if self.results_list.count() <= 1:
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Results", "", "CSV Files (*.csv);;Text Files (*.txt)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', newline='', encoding='utf-8') as file:
                    writer = csv.writer(file)
                    writer.writerow(['Target', 'Port', 'Type', 'Status'])
                    
                    for i in range(1, self.results_list.count()):
                        item = self.results_list.item(i)
                        if not item.isHidden():
                            item_text = item.text()
                            parts = item_text.split()
                            if len(parts) >= 4:
                                target = parts[0]
                                port = parts[1]
                                scan_type = parts[2]
                                status = ' '.join(parts[3:])
                                writer.writerow([target, port, scan_type, status])
                
                self.progress_label.setText(f"Results saved to {file_path}")
            except Exception as e:
                self.progress_label.setText(f"Error saving file: {str(e)}")
    
    def ip_to_int(self, ip):
        try:
            parts = ip.split('.')
            return int(parts[0]) * 256**3 + int(parts[1]) * 256**2 + int(parts[2]) * 256 + int(parts[3])
        except:
            return 0
    
    # ... (остальные методы остаются без изменений, начиная с resolve_domain и до конца)
    def resolve_domain(self, domain):
        try:
            ips = socket.getaddrinfo(domain, None, socket.AF_INET)
            return list(set(ip[4][0] for ip in ips))
        except:
            return []
    
    def get_targets(self):
        targets = []
        target_type = self.target_type.currentText()
        
        if target_type == "Single IP":
            ip = self.single_ip.text().strip()
            if ip:
                targets = [ip]
                
        elif target_type == "IP Range":
            try:
                start = self.ip_to_int(self.start_ip.text())
                end = self.ip_to_int(self.end_ip.text())
                targets = [self.int_to_ip(ip_int) for ip_int in range(start, end + 1)]
            except:
                pass
                
        elif target_type == "Domain":
            domain = self.domain_input.text().strip()
            if domain:
                targets = self.resolve_domain(domain)
        
        return targets
    
    def get_ports(self):
        start_port = self.start_port.value()
        if self.port_mode.currentText() == "Single Port":
            return [start_port]
        else:
            end_port = self.end_port.value()
            return list(range(start_port, end_port + 1))
    
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
            
            sock.send(b'\x10\x00\x00\x00\x00\x00\x00\x00\x00')
            data = sock.recv(1024)
            sock.close()
            
            return "Online" if data and len(data) > 0 else "Offline"
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
            item.setForeground(QColor(0, 128, 0))
        elif "Offline" in status:
            item.setForeground(QColor(255, 0, 0))
        else:
            item.setForeground(QColor(128, 128, 128))
            
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
            delay_ms = self.delay_spinbox.value()
            
            if not targets:
                self.progress_label.setText("Error: No valid targets found")
                return
            
            if not ports:
                self.progress_label.setText("Error: No valid ports specified")
                return
            
            total_targets = len(targets) * len(ports)
            self.update_progress(0, total_targets)
            
            with ThreadPoolExecutor(max_workers=50) as executor:
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
                        
                        if delay_ms > 0:
                            time.sleep(delay_ms / 1000.0)
                            
                    except:
                        continue
            
            self.scanning = False
            self.update_buttons_state()
            self.progress_label.setText("Scan completed" if scanned == total_targets else "Scan stopped")
            
        except Exception as e:
            self.progress_label.setText(f"Error: {str(e)}")
            self.scanning = False
            self.update_buttons_state()
    
    def update_buttons_state(self):
        self.scan_button.setEnabled(not self.scanning)
        self.clear_scan_button.setEnabled(not self.scanning)
        self.clear_button.setEnabled(not self.scanning)
        self.stop_button.setEnabled(self.scanning)
        self.sort_button.setEnabled(not self.scanning)
        self.save_sort_btn.setEnabled(not self.scanning)
    
    def start_scan(self):
        if not self.scanning:
            self.scanning = True
            self.update_buttons_state()
            self.progress_label.setText("Starting scan...")
            threading.Thread(target=self.scan_thread, daemon=True).start()
    
    def clear_and_scan(self):
        self.clear_results()
        self.start_scan()
    
    def clear_results(self):
        self.results_list.clear()
        self.setup_list_header()
        # Reset sort buttons
        self.sort_status_btn.setChecked(False)
        self.sort_status_btn.setText("Status: Online")
        # Show all items if they were hidden
        for i in range(self.results_list.count()):
            item = self.results_list.item(i)
            if item:
                item.setHidden(False)
    
    def stop_scan(self):
        self.scanning = False
        self.progress_label.setText("Stopping scan...")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    scanner = IPScanner()
    scanner.show()
    sys.exit(app.exec())
