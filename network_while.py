import sys
import os
import time
import subprocess
from scapy.all import sniff, wrpcap
import json
import requests
import pandas as pd
import re
from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtCore import QTimer
Threshold = 50
pcap_file_directory = os.path.join(os.getcwd(), 'output', 'pcap')
network_results = [[]]


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
    cd_command = os.path.join(pcap_file_directory[:-11], 'bin')
    os.chdir(cd_command)
    bat_command = f'cfm.bat "{pcap_file_directory}" "{pcap_file_directory[:-4]}\\csv"'
    try:
        subprocess.run(bat_command, shell=True, check=True)
    except subprocess.CalledProcessError:
        pass


def process_csv_file(csv_file_path):
    try:
        api_url = 'https://malwaredetection.onrender.com'
        df = pd.read_csv(csv_file_path)
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
        delete_file(csv_file_path)
        return [["hii raaa", "mental", "0", "100"]]

    except Exception as e:
        print("An error occurred:", str(e))


def show_popup(result):
    msg_box = QMessageBox()
    msg_box.setIcon(QMessageBox.Information)
    msg_box.setText(result)
    msg_box.setWindowTitle("Prediction Result")
    msg_box.exec_()


def loop_comp(interface, capture_duration1):
    pcap_file_path = capture_packets(interface, pcap_file_directory, capture_duration1)
    if pcap_file_path is not None:
        run_flow_analysis()
        if pcap_file_directory is not None:
            label = process_csv_file(pcap_file_directory[:-4] + "csv" + pcap_file_path[-32 + 8:-4] + "pcap_Flow.csv")
            delete_file(pcap_file_path)
            return label


def loop_starter(a, b, c):
    app = QApplication(sys.argv)  # Initialize QApplication
    while True:
        try:
            l = loop_comp(a, b)
            check = re.search(r"\d+", l[-1])
            if int(check.group()) >= Threshold:
                fin = l[-1]
                alg = fin.split()
                result = "Our application predicts your network is under " + alg[
                    -1] + "attack. Make sure your network is safe; this may also be a false positive."
                show_popup(result)
            time.sleep(c)
        except Exception as e:
            print(e)
    sys.exit(app.exec_())  # Ensure proper application exit


if __name__ == "__main__":
    while True:
        interface_to_capture = "Wi-Fi"
        capture_duration = 10
        wait_duration = 10
        loop_starter(interface_to_capture, capture_duration, wait_duration)
