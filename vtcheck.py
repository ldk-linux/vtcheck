import requests
import time
import sys
import os

API_KEY = os.environ['VIRUSTOTAL_API_TOKEN']  # Replace with your VirusTotal API key
VT_FILE_SCAN_URL = 'https://www.virustotal.com/api/v3/files'
VT_REPORT_URL = 'https://www.virustotal.com/api/v3/analyses/'

def submit_file(file_path):
    with open(file_path, 'rb') as file:
        files = {'file': (file_path, file)}
        headers = {'x-apikey': API_KEY}
        response = requests.post(VT_FILE_SCAN_URL, files=files, headers=headers)
        if response.status_code == 200:
            return response.json()['data']['id']
        else:
            print(f"Error submitting file: {response.status_code} {response.text}")
            return None

def get_analysis_results(analysis_id):
    headers = {'x-apikey': API_KEY}
    response = requests.get(f"{VT_REPORT_URL}{analysis_id}", headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error retrieving results: {response.status_code} {response.text}")
        return None
    
def get_file_results(file_id):
    headers = {'x-apikey': API_KEY}
    response = requests.get(f"{VT_FILE_SCAN_URL}/{file_id}", headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error retrieving file results: {response.status_code} {response.text}")
        return None

def check_suspicious_content(file_path):

    analysis_id = submit_file(file_path)
    if not analysis_id:
        print("Failed to submit file.")
        return
    
    bname = os.path.basename(file_path)
    print("File " + bname + " submitted successfully. Waiting for analysis results...")

    done = False
    file_id = None
    while not done:
        time.sleep(30)
        results = get_analysis_results(analysis_id)
        if not results:
            print("Failed to retrieve results.")
            return
        if results['data']['attributes']['status'] == 'completed':
            file_id = results['meta']['file_info']['sha256']
            done = True
        elif results['data']['attributes']['status'] != 'queued':
            print("Received unexpected analys result status: {results['status']}")
            return
        
    print(f"Analysis complete. File ID: {file_id}. Waiting for sandbox analysis...")
    time.sleep(300)
    results = get_file_results(file_id)

    # Process general scan results
    if 'attributes' in results['data'] and 'last_analysis_stats' in results['data']['attributes']:
        if 'malicious' in results['data']['attributes']['last_analysis_stats']:
            malicious_count = results['data']['attributes']['last_analysis_stats']['malicious']
        else:
            malicious_count = 0
    if malicious_count > 0:
        print(f"Suspicious content found in general scan! {malicious_count} engines flagged the file as malicious.")
        return
    else:
        print("No suspicious content found in general scan.")

    # Check sandbox results
    if 'attributes' in results['data'] and 'sandbox_verdicts' in results['data']['attributes']:
        sandbox_results = results['data']['attributes']['sandbox_verdicts']
        if sandbox_results:
            for sandbox in sandbox_results:
                if sandbox_results[sandbox]['category'] == 'malicious':
                    print(f"Sandbox analysis flagged the file as malicious by {sandbox}.")
                else:
                    print(f"Sandbox analysis by {sandbox} did not flag the file as malicious.")
        else:
            print("No sandbox analysis results available.")
    else:
        print("No sandbox analysis available.")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python vtcheck.py <file to check>" + os.linesep)
        exit(-1)
    check_suspicious_content(sys.argv[1])
    print("--------------------------------")
