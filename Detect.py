import sys
import os
import time
import json
import subprocess
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QAction, QLabel, QPushButton
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from scapy.all import sniff, wrpcap
from tabulate import tabulate
import requests
import pandas as pd


pcap_file_directory = f"{os.getcwd()}\\output\\pcap"
network_results = [[]]


class MalwareDetectionApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Malware Detection App")
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.analysis_thread = AnalysisThread(self)
        self.analysis_thread.finished.connect(self.show_network_result)
        self.create_menu()
        self.setStyleSheet(
            "QMainWindow { background-color: #f0f0f0; }"
            "QMenuBar { background-color: #333; color: #fff; }"
            "QMenuBar::item { background-color: #333; padding: 8px 16px; }"
            "QMenuBar::item:selected { background-color: #555; }"
            "QLabel { font-size: 16px; padding: 20px; }"
            "QPushButton { font-size: 14px; padding: 8px; }"
        )
        self.show_initial_content()

    def create_menu(self):
        menubar = self.menuBar()
        menu = menubar.addMenu('Menu')
        actions = [
            ('Home', self.show_initial_content),
            ('Network Analysis', self.show_network_content),
            ('System Analysis', self.show_system_content),
            ('Document Analysis', self.show_document_content)
        ]
        for action_text, callback in actions:
            menu_action = QAction(action_text, self)
            menu_action.triggered.connect(callback)
            menu.addAction(menu_action)

    def clear_layout(self):
        for i in reversed(range(self.main_layout.count())):
            widget = self.main_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)

    def show_initial_content(self):
        self.clear_layout()
        label = QLabel("Welcome to the Malware detection app from G91", self)
        self.main_layout.addWidget(label, alignment=Qt.AlignCenter)

    def show_network_content(self):
        self.clear_layout()
        option_label = QLabel("Click to start Network Analysis", self)
        self.main_layout.addWidget(option_label, alignment=Qt.AlignCenter)
        option_button = QPushButton("Start", self)
        option_button.clicked.connect(self.start_network_analysis)
        self.main_layout.addWidget(option_button, alignment=Qt.AlignCenter)

    def show_system_content(self):
        self.clear_layout()
        option_label = QLabel("Click to start System Analysis", self)
        self.main_layout.addWidget(option_label, alignment=Qt.AlignCenter)
        option_button = QPushButton("Start", self)
        option_button.clicked.connect(self.start_system_analysis)
        self.main_layout.addWidget(option_button, alignment=Qt.AlignCenter)

    def show_document_content(self):
        self.clear_layout()
        option_label = QLabel("Click to start Document Analysis", self)
        self.main_layout.addWidget(option_label, alignment=Qt.AlignCenter)
        option_button = QPushButton("Select file", self)
        option_button.clicked.connect(self.start_document_analysis)
        self.main_layout.addWidget(option_button, alignment=Qt.AlignCenter)

    def start_network_analysis(self):
        self.clear_layout()
        option_label = QLabel("Processing your network", self)
        self.main_layout.addWidget(option_label, alignment=Qt.AlignCenter)
        self.analysis_thread.start()

    def start_document_analysis(self):
        self.clear_layout()
        option_label = QLabel("No function has been assigned here, this will be a future goal.", self)
        self.main_layout.addWidget(option_label, alignment=Qt.AlignCenter)

    def start_system_analysis(self):
        self.clear_layout()
        option_label = QLabel("No function has been assigned here, this will be a future goal.", self)
        self.main_layout.addWidget(option_label, alignment=Qt.AlignCenter)

    def show_network_result(self):
        self.clear_layout()
        global network_results
        data = network_results[:-1]
        if data:
            headers = ["Model name", "Possibility percentage", "Attack type"]
            table = tabulate(data, headers)
            option_label = QLabel(table, self)
            self.main_layout.addWidget(option_label, alignment=Qt.AlignCenter)
            accuracy_note_label = QLabel(
                network_results[-1]+"\nNote: The accuracy of the table may not be perfect due to the constraint of open source data.", self)
            self.main_layout.addWidget(accuracy_note_label, alignment=Qt.AlignCenter)
        else:
            option_label = QLabel("Something went wrong or your network did not contain any packets or data.", self)
            self.main_layout.addWidget(option_label, alignment=Qt.AlignCenter)


class AnalysisThread(QThread):
    finished = pyqtSignal()

    def __init__(self, parent):
        super().__init__(parent)

    def run(self):
        global network_results
        network_results = loop_comp("Wi-Fi", 30)
        self.finished.emit()


def delete_file(file_path):
    try:
        os.remove(file_path)
    except Exception as e:
        print(f"Error deleting file {file_path}: {e}")


def capture_packets(interface, output_folder, duration):
    timestamp = time.strftime("%Y--%m--%d_%H-%M")
    pcap_file_path = os.path.join(output_folder, f"{timestamp}.pcap")
    try:
        packets = sniff(iface=interface, timeout=duration, store=True)
        wrpcap(pcap_file_path, packets)
        return pcap_file_path
    except KeyboardInterrupt:
        return None


def run_flow_analysis():
    cd_command = pcap_file_directory[:-11] + "\\bin"
    os.chdir(cd_command)
    bat_command = f'cfm.bat "{pcap_file_directory}" "{pcap_file_directory[:-4]}\\csv"'
    try:
        subprocess.run(bat_command, shell=True, check=True)
    except subprocess.CalledProcessError:
        pass


def process_csv_file(csv_file_path):
    try:
        print("here")
        api_url = 'https://malwaredetection.onrender.com'
        df = pd.read_csv(csv_file_path)
        delete_file(csv_file_path)
        df.to_json("dummy.json")
        with open('dummy.json') as f:
            data = json.load(f)
        delete_file("dummy.json")
        data_to_send = data
        response = requests.post(api_url, json=data_to_send)
        if response.status_code == 200:
            api_response = response.json()
            return api_response
        else:
            print("Error:", response.status_code, response.text)
        return [["Our api is currently not responding pls try again later"]]

    except Exception as e:
        print("An error occurred:", str(e))


def loop_comp(interface, capture_duration1):
    pcap_file_path = capture_packets(interface, pcap_file_directory, capture_duration1)
    if pcap_file_path is not None:
        run_flow_analysis()
        if pcap_file_directory is not None:
            label = process_csv_file(pcap_file_directory[:-4] + "csv" + pcap_file_path[-32 + 8:-4] + "pcap_Flow.csv")
            print(label)
            delete_file(pcap_file_path)
            return label


def main():
    app = QApplication(sys.argv)
    window = MalwareDetectionApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
