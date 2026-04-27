from flask import Flask, send_from_directory, make_response
import os
import socket
import subprocess
from io import StringIO
import sys

app = Flask(__name__)

# Core threat detection logic
def run_detection():
    output = StringIO()
    sys.stdout = output

    print("=== SecureZone Threat Detection Tool ===")

    # 1. Detect Suspicious Files
    def find_suspicious_files(directory, extensions=['.exe', '.bat', '.vbs']):
        print("\n[!] Scanning for suspicious files...")
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.lower().endswith(tuple(ext.lower() for ext in extensions)):
                    print(f"Suspicious file found: {os.path.join(root, file)}")

    # 2. Detect Open Ports
    def scan_open_ports():
        print("\n[!] Checking open ports...")
        ports = [21, 22, 23, 80, 443, 445, 3389]
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            if result == 0:
                print(f"Port {port} is OPEN")
            sock.close()

    # 3. Detect Suspicious Processes (without psutil)
    def detect_processes_basic():
        print("\n[!] Listing running processes (basic)...")
        try:
            tasks = subprocess.check_output(['tasklist'], shell=True).decode()
            suspicious_keywords = ['keylogger', 'malware', 'trojan']
            for line in tasks.splitlines():
                if any(keyword in line.lower() for keyword in suspicious_keywords):
                    print(f"Suspicious process found: {line}")
        except Exception as e:
            print(f"Error: {e}")

    # Run all detection
    find_suspicious_files("C:\\")
    scan_open_ports()
    detect_processes_basic()

    sys.stdout = sys.__stdout__
    return output.getvalue()

# Flask routes
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/run-scan')
def scan():
    results = run_detection()
    response = make_response(results)
    response.headers["Content-Disposition"] = "attachment; filename=scan_result.txt"
    response.headers["Content-Type"] = "text/plain"
    return response

if __name__ == '__main__':
    app.run(debug=True)
