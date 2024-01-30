import os
import psutil
import hashlib
import requests
from PyQt5 import QtWidgets
from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton
from PyQt5.QtGui import QFont, QCursor
from PyQt5.QtCore import QTimer, Qt


class VirusTotalChecker:
    def __init__(self, api_key):
        self.api_key = api_key

    def get_file_hash(self, file_path):
        try:
            with open(file_path, 'rb') as file:
                file_data = file.read()
                hash_object = hashlib.sha256()
                hash_object.update(file_data)
                return hash_object.hexdigest()
        except Exception as e:
            print(f"Error hashing file {file_path}: {e}")
            return None

    def check_hash_in_vt(self, file_hash):
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {'x-apikey': self.api_key}

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                result = response.json()
                if 'data' in result and 'attributes' in result['data']:
                    attributes = result['data']['attributes']
                    if 'last_analysis_stats' in attributes:
                        stats = attributes['last_analysis_stats']
                        if stats['malicious'] > 0 or stats['suspicious'] > 0:
                            return False  # Unsafe file found
                return True  # File safe or not scanned on VirusTotal
        except Exception as e:
            print(f"Error checking hash in VirusTotal: {e}")
        return False  # Error occurred or file not found in VirusTotal


def find_usb_path():
    drives = psutil.disk_partitions(all=True)
    for drive in drives:
        if 'removable' in drive.opts:
            return drive.mountpoint
    return None


def scan_usb_drive(usb_path):
    api_key = '90282f0538eced71fe692d2e0870af3dd015dc80059734b466338c5bbce07f63'
    vt_checker = VirusTotalChecker(api_key)

    if usb_path:
        files_in_usb = list_files_in_usb(usb_path)
        if files_in_usb:
            unsafe_files = False
            for file in files_in_usb:
                file_hash = vt_checker.get_file_hash(file)
                if file_hash:
                    result = vt_checker.check_hash_in_vt(file_hash)
                    if not result:
                        unsafe_files = True
                        break
            if unsafe_files:
                return "USB drive is unsafe."
            else:
                return "USB drive is safe."
        else:
            return "No files found in USB."
    else:
        return "No USB device detected."


def list_files_in_usb(usb_path):
    if usb_path:
        files = []
        for file_path in os.listdir(usb_path):
            files.append(os.path.join(usb_path, file_path))
        return files
    return []


class ScanProgressWindow(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Scanning Progress")
        self.setFixedSize(300, 100)
        self.setStyleSheet("background-color: black;")

        layout = QtWidgets.QVBoxLayout()

        self.scanning_label = QtWidgets.QLabel("Scanning...", self)
        self.scanning_label.setAlignment(Qt.AlignCenter)  # Center-align the label text
        self.scanning_label.setStyleSheet("font-size: 16px; color: white; font-weight: bold; font-family: Akronim;")
        layout.addWidget(self.scanning_label)

        self.setLayout(layout)

        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.update_text)
        self.counter = 0
        self.timer.start(300)  # Adjust the timing of the animation here

    def update_text(self):
        dots = "." * (self.counter % 4)  # Change the number to modify animation speed
        self.scanning_label.setText(f"Scanning{dots}")
        self.counter += 1

    def closeEvent(self, event):
        self.timer.stop()
        super().closeEvent(event)


class MainWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("USB Scan")
        self.setFixedSize(400, 200)
        self.setStyleSheet("background-color: black;")

        # Create the check USB timer and start it
        self.check_usb_timer = QtCore.QTimer(self)
        self.check_usb_timer.timeout.connect(self.check_usb)
        self.check_usb_timer.start(1000)  # Check USB status every second

        layout = QtWidgets.QVBoxLayout()

        label = QtWidgets.QLabel("    " * 6 + "USB inserted.\n\n" + "   " * 3 + " Would you like to scan for viruses?")
        label.setStyleSheet("font-size: 16px; color: white; font-weight: bold; font-family: Akronim;")
        layout.addWidget(label)

        self.scan_button = QtWidgets.QPushButton('Scan', self)
        self.scan_button.clicked.connect(self.scan_button_clicked)
        self.scan_button.setStyleSheet(
            'QPushButton {background-color: #3498db; color: white; border: 2px solid #2980b9; border-radius: 5px;'
            'padding: 5px; font-size: 18px; font-weight: bold;}'
            'QPushButton:pressed {background-color: white; color: #3498db;}'
            'QPushButton:hover {background-color: white; color: #3498db; border: 2px solid #2980b9;}'
        )
        self.scan_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        layout.addWidget(self.scan_button)

        self.dont_scan_button = QtWidgets.QPushButton("Don't Scan", self)
        self.dont_scan_button.clicked.connect(self.dont_scan_button_clicked)
        self.dont_scan_button.setStyleSheet(
            'QPushButton {background-color: #3498db; color: white; border: 2px solid #2980b9; border-radius: 5px;'
            'padding: 5px; font-size: 18px; font-weight: bold;}'
            'QPushButton:pressed {background-color: white; color: #3498db;}'
            'QPushButton:hover {background-color: white; color: #3498db; border: 2px solid #2980b9;}'
        )
        self.dont_scan_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        layout.addWidget(self.dont_scan_button)

        self.setLayout(layout)
        self.check_usb()  # Check USB status immediately

    # Define check_usb method to check USB status
    def check_usb(self):
        usb_path = self.find_usb_path()
        if usb_path:
            self.show()  # Show the main window if USB is detected
            self.check_usb_timer.stop()  # Stop checking USB status
        else:
            self.hide()

    def find_usb_path(self):
        drives = psutil.disk_partitions(all=True)
        for drive in drives:
            if 'removable' in drive.opts:
                return drive.mountpoint
        return None

    def scan_button_clicked(self):
        usb_path = self.find_usb_path()
        if usb_path:
            scan_progress = ScanProgressWindow(self)
            scan_progress.show()
            QtWidgets.QApplication.processEvents()  # Process events to update UI
            scan_result = scan_usb_drive(usb_path)
            scan_progress.close()
            show_popup("Scan Result", scan_result)
        else:
            show_popup("Scan Result", "No USB device detected.")

    def dont_scan_button_clicked(self):
        self.close()  # Close the main window when "Don't Scan" is clicked


def show_popup(title, message):
    msg_box = QtWidgets.QMessageBox()
    msg_box.setWindowTitle(title)
    msg_box.setText(message)
    msg_box.setStyleSheet("background-color: black; color: white; font-weight: bold;")
    msg_box.setFixedSize(300, 100)

    # Get the OK button in the message box
    ok_button = msg_box.addButton(QtWidgets.QMessageBox.Ok)
    ok_button.setStyleSheet(
        "QPushButton {background-color: #3498db; color: white; border: 2px solid #2980b9; border-radius: 5px; padding: 3px 10px; font-size: 14px; font-weight: bold;}"
        "QPushButton:hover {background-color: white; color: #3498db; border: 2px solid #2980b9;}"
        "QPushButton:pressed {background-color: #3498db; color: white; border: 2px solid #2980b9;}"
    )
    ok_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))

    msg_box.exec_()


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    main_window = MainWindow()
    sys.exit(app.exec_())
