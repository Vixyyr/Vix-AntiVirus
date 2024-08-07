import os
import requests
import hashlib
import sys
import logging
import time
import threading
import time

API_KEY = 'fdb3cb3696eb5aff9c9d5836ae39239b001c5aad5149ef972679bbb742a3103d'
API_URL = 'https://www.virustotal.com/api/v3/files'
UPLOAD_URL = 'https://www.virustotal.com/api/v3/files'

HEADERS = {
    'x-apikey': API_KEY
}

logging.basicConfig(filename='scan_log.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

FILE_EXTENSIONS = {'.zip', '.rar', '.exe', '.bat'}

SHORT_SCAN_DURATION = 30  
DEEP_SCAN_DURATION = 60   

is_real_time_protection_on = True

def calculate_hash(file_path):
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as file:
            buf = file.read(8192)
            while len(buf) > 0:
                hasher.update(buf)
                buf = file.read(8192)
    except (PermissionError, FileNotFoundError, OSError) as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return None
    return hasher.hexdigest()

def scan_file_with_virustotal(file_path):
    file_hash = calculate_hash(file_path)
    if file_hash:
        response = requests.get(f"{API_URL}/{file_hash}", headers=HEADERS)
        
        if response.status_code == 200:
            result = response.json()
            scan_results = result.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
            
            threat_detected = False
            threat_details = []
            for engine, analysis in scan_results.items():
                if analysis.get('category') == 'malicious':
                    threat_details.append(f"{engine}: {analysis.get('result')}")
                    threat_detected = True
            
            if threat_detected:
                with open('threats.txt', 'a') as threats_file:
                    threats_file.write(f"--------------------------\n")
                    threats_file.write(f"{os.path.basename(file_path)} - {'; '.join(threat_details)}\n")
                    threats_file.write(f"--------------------------\n")
                
                logging.warning(f"Threat detected in file {file_path}: {'; '.join(threat_details)}")
            else:
                logging.info(f"No threat detected in {file_path}.")
            return threat_detected
        elif response.status_code == 404:
            logging.info(f"File not found in VirusTotal database: {file_path}")
            upload_file(file_path)
            return False
        else:
            logging.error(f"Error: {response.status_code} - {response.text}")
            return False
    return False

def upload_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            response = requests.post(UPLOAD_URL, headers=HEADERS, files={'file': file})
        
        if response.status_code == 200:
            result = response.json()
            logging.info(f"File uploaded for analysis: {file_path}. Analysis ID: {result.get('data', {}).get('id')}")
        else:
            logging.error(f"Failed to upload file: {response.status_code} - {response.text}")
    except Exception as e:
        logging.error(f"Exception occurred during file upload: {e}")

def print_progress(duration, scan_type):
    """Simulate a progress bar by printing progress to the console."""
    num_steps = 20 
    step_duration = duration / num_steps
    for step in range(num_steps + 1):
        time.sleep(step_duration)
        progress = int((step / num_steps) * 100)
        sys.stdout.write(f"\r{scan_type} Progress: [{'#' * (step)}{'.' * (num_steps - step)}] {progress}%")
        sys.stdout.flush()
    print(f"\n{scan_type} completed!")

def scan_file(file_path):
    """Scan individual file with real-time protection check."""
    if is_real_time_protection_on:
        scan_file_with_virustotal(file_path)

def scan_directories(directories, scan_duration):
    """Scan files in specified directories."""
    for directory in directories:
        if os.path.exists(directory):
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if any(file.lower().endswith(ext) for ext in FILE_EXTENSIONS):
                        file_path = os.path.join(root, file)
                        logging.info(f"Scanning: {file_path}")
                        scan_file(file_path)
        else:
            logging.warning(f"Directory does not exist: {directory}")

def toggle_real_time_protection():
    """Toggle real-time protection status."""
    global is_real_time_protection_on
    if is_real_time_protection_on:
        print("Turning off real-time protection.")
    else:
        print("Turning on real-time protection.")
    is_real_time_protection_on = not is_real_time_protection_on

def main():
    """Main function to handle user input and execute commands."""
    global is_real_time_protection_on
    
    while True:
        print("Vix AntiVirus")
        time.sleep(3)
        print("\nOptions:")
        print("1. Short Scan")
        print("2. Deep Scan")
        print("3. Turn Off Real-Time Protection" if is_real_time_protection_on else "4. Turn Real-Time Protection On")
        print("4. Exit")

        choice = input("Enter your choice (1-4): ")
        
        if choice == '1':
            print("Starting short scan...")
            open('threats.txt', 'w').close()
            scan_directories(directories_to_scan, SHORT_SCAN_DURATION)
            print("Short scan complete. Check 'scan_log.txt' and 'threats.txt' for details.")
        elif choice == '2':
            print("Starting deep scan...")
            open('threats.txt', 'w').close()
            scan_directories(directories_to_scan, DEEP_SCAN_DURATION)
            print("Deep scan complete. Check 'scan_log.txt' and 'threats.txt' for details.")
        elif choice == '3' and is_real_time_protection_on:
            toggle_real_time_protection()
        elif choice == '4' and not is_real_time_protection_on:
            toggle_real_time_protection()
        elif choice == '4':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    if os.name == 'nt': 
        home = os.path.expanduser("~")
        directories_to_scan = [
            os.path.join(home, 'Downloads'),
            os.path.join(home, 'Documents'),
            os.path.join(home, 'Desktop')
        ]
    else:
        home = os.path.expanduser("~")
        directories_to_scan = [
            os.path.join(home, 'Downloads'),
            os.path.join(home, 'Documents'),
            os.path.join(home, 'Desktop')
        ]
    
    main()
