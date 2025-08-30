import sys
import csv
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QTableWidget, QTableWidgetItem,
                             QLabel, QFileDialog, QHeaderView, QProgressBar, QMessageBox,
                             QMenu, QInputDialog)
from PyQt6.QtCore import Qt, pyqtSignal, QObject
from PyQt6.QtGui import QColor, QFont, QAction

class ScannerSignals(QObject):
    update_signal = pyqtSignal(str, str, str, str)
    progress_signal = pyqtSignal(int, int)

class IPMCChecker(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IPMC Checker - Minecraft Server Checker")
        self.setGeometry(100, 100, 1000, 600)
        
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
        self.sort_button.clicked.connect(self.show_sort_menu)
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
        
        self.export_button = QPushButton("Export Table")
        self.export_button.clicked.connect(self.export_table)
        button_layout.addWidget(self.export_button)
        
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
        self.table.setColumnCount(5)  # Added column for copy button
        self.table.setHorizontalHeaderLabels(["Target", "Port", "Status", "Version", "Action"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.setSortingEnabled(True)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_table_context_menu)
        
        # Set column widths
        self.table.setColumnWidth(0, 200)  # Target
        self.table.setColumnWidth(1, 80)   # Port
        self.table.setColumnWidth(2, 120)  # Status
        self.table.setColumnWidth(3, 150)  # Version
        self.table.setColumnWidth(4, 150)  # Action
        
        layout.addWidget(self.table)
        
    def show_table_context_menu(self, position):
        context_menu = QMenu(self)
        
        # Sort submenu
        sort_menu = context_menu.addMenu("Sort by")
        
        sort_status_action = QAction("Status [MC/Not MC]", self)
        sort_status_action.triggered.connect(lambda: self.sort_by_status_mc())
        sort_menu.addAction(sort_status_action)
        
        sort_version_action = QAction("Version", self)
        sort_version_action.triggered.connect(lambda: self.sort_by_version())
        sort_menu.addAction(sort_version_action)
        
        # Copy action
        copy_action = QAction("Copy Data", self)
        copy_action.triggered.connect(self.copy_selected_data)
        context_menu.addAction(copy_action)
        
        context_menu.exec(self.table.mapToGlobal(position))
    
    def copy_selected_data(self):
        selected_items = self.table.selectedItems()
        if selected_items:
            row = selected_items[0].row()
            target = self.table.item(row, 0).text()
            port = self.table.item(row, 1).text()
            status = self.table.item(row, 2).text()
            version = self.table.item(row, 3).text()
            
            text = f"{target}:{port} - {status} - {version}"
            QApplication.clipboard().setText(text)
    
    def show_sort_menu(self):
        sort_menu = QMenu(self)
        
        sort_status_action = QAction("Status [MC/Not MC]", self)
        sort_status_action.triggered.connect(lambda: self.sort_by_status_mc())
        sort_menu.addAction(sort_status_action)
        
        sort_version_action = QAction("Version", self)
        sort_version_action.triggered.connect(lambda: self.sort_by_version())
        sort_menu.addAction(sort_version_action)
        
        export_action = QAction("Export Table", self)
        export_action.triggered.connect(self.export_table)
        sort_menu.addAction(export_action)
        
        sort_menu.exec(self.sort_button.mapToGlobal(self.sort_button.rect().bottomLeft()))
    
    def sort_by_status_mc(self):
        # Sort by MC status (Worked first, then others)
        self.table.sortItems(2, Qt.SortOrder.DescendingOrder)
    
    def sort_by_version(self):
        # Sort by version
        self.table.sortItems(3, Qt.SortOrder.AscendingOrder)
    
    def export_table(self):
        if self.table.rowCount() == 0:
            QMessageBox.warning(self, "Warning", "No data to export!")
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Table", "", "CSV Files (*.csv);;Text Files (*.txt)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', newline='', encoding='utf-8') as file:
                    writer = csv.writer(file)
                    writer.writerow(['Target', 'Port', 'Status', 'Version'])
                    
                    for row in range(self.table.rowCount()):
                        target = self.table.item(row, 0).text()
                        port = self.table.item(row, 1).text()
                        status = self.table.item(row, 2).text()
                        version = self.table.item(row, 3).text()
                        writer.writerow([target, port, status, version])
                
                QMessageBox.information(self, "Success", f"Table exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export: {str(e)}")
    
    def load_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open File from IPScanner", "", "All Files (*.*);;CSV Files (*.csv);;Text Files (*.txt)"
        )
        
        if file_path:
            try:
                self.server_data = []
                
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                    content = file.read().splitlines()
                    
                    for line in content:
                        line = line.strip()
                        if not line or line.startswith(('Target', 'IP', '#', '---')):
                            continue
                            
                        # Handle both CSV and TXT formats
                        if ',' in line:
                            # CSV format
                            parts = [part.strip() for part in line.split(',')]
                        else:
                            # TXT format (space separated)
                            parts = line.split()
                        
                        if len(parts) >= 4:  # Target, Port, Type, Status
                            target = parts[0]
                            port = parts[1]
                            status = parts[3]
                            
                            # Only add Online servers or Minecraft related
                            if status == "Online" or "Minecraft" in ' '.join(parts):
                                self.server_data.append((target, port))
                        elif len(parts) >= 2:  # Just Target and Port
                            target = parts[0]
                            port = parts[1]
                            self.server_data.append((target, port))
                
                self.update_table_from_data()
                self.progress_label.setText(f"Loaded {len(self.server_data)} servers from {file_path}")
                
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
            
            # Add copy button
            copy_button = QPushButton("Copy IP:Port")
            copy_button.clicked.connect(lambda checked, r=row: self.copy_ip_port(r))
            self.table.setCellWidget(row, 4, copy_button)
    
    def copy_ip_port(self, row):
        target = self.table.item(row, 0).text()
        port = self.table.item(row, 1).text()
        text = f"{target}:{port}"
        QApplication.clipboard().setText(text)
        self.progress_label.setText(f"Copied: {text}")
    
    def check_minecraft_server(self, target, port):
        try:
            # Clean target from any extra text
            clean_target = target.split()[0].strip()
            
            # Try to connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((clean_target, int(port)))
            sock.close()
            
            if result == 0:
                try:
                    from mcstatus import JavaServer
                    server = JavaServer.lookup(f"{clean_target}:{port}")
                    status = server.status()
                    return "Worked", f"{status.version.name}", clean_target
                except:
                    return "Worked (No MC)", "Unknown", clean_target
            else:
                return "Not worked", "Unknown", clean_target
                
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
                # Update target (cleaned)
                self.table.setItem(row, 0, QTableWidgetItem(target))
                
                # Update status with color
                status_item = QTableWidgetItem(status)
                if "Worked" in status:
                    status_item.setForeground(QColor(0, 128, 0))
                elif "Not worked" in status:
                    status_item.setForeground(QColor(255, 0, 0))
                elif "Error" in status:
                    status_item.setForeground(QColor(255, 165, 0))
                else:
                    status_item.setForeground(QColor(128, 128, 128))
                self.table.setItem(row, 2, status_item)
                
                # Update version
                version_item = QTableWidgetItem(version)
                self.table.setItem(row, 3, version_item)
                
                # Update copy button with cleaned target
                copy_button = QPushButton("Copy IP:Port")
                copy_button.clicked.connect(lambda checked, r=row: self.copy_ip_port(r))
                self.table.setCellWidget(row, 4, copy_button)
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

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    try:
        from mcstatus import JavaServer
    except ImportError:
        QMessageBox.critical(None, "Error", 
            "mcstatus library is required!\nInstall with: pip install mcstatus"
        )
        sys.exit(1)
    
    checker = IPMCChecker()
    checker.show()
    sys.exit(app.exec())
