import sys
import csv
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QTableWidget, QTableWidgetItem,
                             QLabel, QFileDialog, QHeaderView, QProgressBar, QMessageBox)
from PyQt6.QtCore import Qt, pyqtSignal, QObject
from PyQt6.QtGui import QColor, QFont

class ScannerSignals(QObject):
    update_signal = pyqtSignal(str, str, str, str)
    progress_signal = pyqtSignal(int, int)

class IPMCChecker(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IPMC Checker - Minecraft Server Checker")
        self.setGeometry(100, 100, 900, 600)
        
        self.scanning = False
        self.scanned_servers = 0
        self.total_servers = 0
        self.server_data = []
        
        self.signals = ScannerSignals()
        self.signals.update_signal.connect(self.update_table)
        self.signals.progress_signal.connect(self.update_progress)
        
        self.init_ui()
        
    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Top buttons panel
        button_layout = QHBoxLayout()
        
        self.load_button = QPushButton("Load Table")
        self.load_button.clicked.connect(self.load_file)
        button_layout.addWidget(self.load_button)
        
        self.sort_button = QPushButton("Sort")
        self.sort_button.clicked.connect(self.sort_table)
        button_layout.addWidget(self.sort_button)
        
        self.scan_button = QPushButton("Scan")
        self.scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.scan_button)
        
        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear_table)
        button_layout.addWidget(self.clear_button)
        
        self.clear_scan_button = QPushButton("Clear + Scan")
        self.clear_scan_button.clicked.connect(self.clear_and_scan)
        button_layout.addWidget(self.clear_scan_button)
        
        layout.addLayout(button_layout)
        
        # Progress area
        progress_layout = QHBoxLayout()
        self.progress_label = QLabel("Ready to load file")
        progress_layout.addWidget(self.progress_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        progress_layout.addWidget(self.progress_bar)
        
        layout.addLayout(progress_layout)
        
        # Results table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Target", "Port", "Status", "Version"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.setSortingEnabled(True)
        
        # Set column widths
        self.table.setColumnWidth(0, 200)  # Target
        self.table.setColumnWidth(1, 80)   # Port
        self.table.setColumnWidth(2, 120)  # Status
        self.table.setColumnWidth(3, 150)  # Version
        
        layout.addWidget(self.table)
        
    def load_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open CSV/TXT File from IPScanner", "", "CSV Files (*.csv);;Text Files (*.txt)"
        )
        
        if file_path:
            try:
                self.server_data = []
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                    if file_path.endswith('.csv'):
                        # Try different CSV formats
                        reader = csv.reader(file)
                        header = next(reader, [])
                        
                        if header and len(header) >= 2:
                            # Determine column indices
                            target_idx = header.index('Target') if 'Target' in header else 0
                            port_idx = header.index('Port') if 'Port' in header else 1
                            status_idx = header.index('Status') if 'Status' in header else 3
                            
                            for row in reader:
                                if len(row) >= max(target_idx, port_idx, status_idx) + 1:
                                    target = row[target_idx].strip()
                                    port = row[port_idx].strip()
                                    status = row[status_idx].strip() if status_idx < len(row) else "Unknown"
                                    
                                    # Only add if status is Online or from Minecraft scan
                                    if status == "Online" or "Minecraft" in str(row):
                                        self.server_data.append((target, port))
                    else:
                        # TXT file parsing
                        for line in file:
                            line = line.strip()
                            if line and not line.startswith(('Target', 'IP', '#')):
                                parts = line.split()
                                if len(parts) >= 4:  # Target Port Type Status
                                    target = parts[0]
                                    port = parts[1]
                                    status = parts[3] if len(parts) > 3 else "Unknown"
                                    
                                    if status == "Online" or "Minecraft" in line:
                                        self.server_data.append((target, port))
                
                self.update_table_from_data()
                self.progress_label.setText(f"Loaded {len(self.server_data)} Minecraft servers")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load file: {str(e)}")
                self.progress_label.setText("Error loading file")
    
    def update_table_from_data(self):
        self.table.setRowCount(len(self.server_data))
        
        for row, (target, port) in enumerate(self.server_data):
            self.table.setItem(row, 0, QTableWidgetItem(target))
            self.table.setItem(row, 1, QTableWidgetItem(port))
            self.table.setItem(row, 2, QTableWidgetItem("Not checked"))
            self.table.setItem(row, 3, QTableWidgetItem("Unknown"))
    
    def check_minecraft_server(self, target, port):
        try:
            # Clean the target (remove domain stuff if needed)
            clean_target = target.split()[0]  # Take only first part if there are spaces
            
            # Try to connect to check if server is online
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((clean_target, int(port)))
            sock.close()
            
            if result == 0:
                # Server is online, try to get Minecraft status
                try:
                    from mcstatus import JavaServer
                    server = JavaServer.lookup(f"{clean_target}:{port}")
                    status = server.status()
                    return "Worked", f"{status.version.name}", clean_target
                except Exception as mc_error:
                    return "Worked (No MC)", "Unknown", clean_target
            else:
                return "Not worked", "Unknown", clean_target
                
        except socket.gaierror:
            return "Invalid host", "Unknown", target
        except ValueError:
            return "Invalid port", "Unknown", target
        except Exception as e:
            return f"Error: {str(e)}", "Unknown", target
    
    def scan_thread(self):
        self.scanning = True
        self.scanned_servers = 0
        self.total_servers = len(self.server_data)
        
        self.signals.progress_signal.emit(0, self.total_servers)
        
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = []
            
            for row, (target, port) in enumerate(self.server_data):
                if not self.scanning:
                    break
                
                futures.append((row, executor.submit(self.check_minecraft_server, target, port)))
            
            for row, future in futures:
                if not self.scanning:
                    break
                
                try:
                    status, version, clean_target = future.result(timeout=10)
                    self.signals.update_signal.emit(str(row), status, version, clean_target)
                    self.scanned_servers += 1
                    self.signals.progress_signal.emit(self.scanned_servers, self.total_servers)
                except:
                    self.signals.update_signal.emit(str(row), "Timeout", "Unknown", target)
                    self.scanned_servers += 1
                    self.signals.progress_signal.emit(self.scanned_servers, self.total_servers)
        
        self.scanning = False
        self.progress_bar.setVisible(False)
        self.progress_label.setText("Scan completed" if self.scanned_servers == self.total_servers else "Scan stopped")
    
    def update_table(self, row_str, status, version, target):
        try:
            row = int(row_str)
            if row < self.table.rowCount():
                # Update status
                status_item = QTableWidgetItem(status)
                if "Worked" in status:
                    status_item.setForeground(QColor(0, 128, 0))  # Green
                elif "Not worked" in status:
                    status_item.setForeground(QColor(255, 0, 0))  # Red
                elif "Error" in status or "Invalid" in status:
                    status_item.setForeground(QColor(255, 165, 0))  # Orange
                else:
                    status_item.setForeground(QColor(128, 128, 128))  # Gray
                
                self.table.setItem(row, 2, status_item)
                
                # Update version
                version_item = QTableWidgetItem(version)
                self.table.setItem(row, 3, version_item)
                
                # Update target (cleaned)
                self.table.setItem(row, 0, QTableWidgetItem(target))
        except:
            pass
    
    def update_progress(self, scanned, total):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(scanned)
        self.progress_bar.setVisible(True)
        percentage = (scanned / total * 100) if total > 0 else 0
        self.progress_label.setText(f"Scanning: {scanned}/{total} ({percentage:.1f}%)")
    
    def start_scan(self):
        if not self.scanning and self.server_data:
            self.progress_label.setText("Starting Minecraft server scan...")
            threading.Thread(target=self.scan_thread, daemon=True).start()
        elif not self.server_data:
            QMessageBox.warning(self, "Warning", "Please load a file first!")
    
    def clear_table(self):
        self.table.setRowCount(0)
        self.server_data = []
        self.progress_label.setText("Table cleared")
        self.progress_bar.setVisible(False)
    
    def clear_and_scan(self):
        self.clear_table()
        self.load_file()
        if self.server_data:
            self.start_scan()
    
    def sort_table(self):
        self.table.sortItems(2, Qt.SortOrder.DescendingOrder)  # Sort by Status

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Check if mcstatus is installed
    try:
        from mcstatus import JavaServer
    except ImportError:
        QMessageBox.critical(None, "Error", 
            "mcstatus library is required!\n"
            "Install it with: pip install mcstatus"
        )
        sys.exit(1)
    
    checker = IPMCChecker()
    checker.show()
    sys.exit(app.exec())
