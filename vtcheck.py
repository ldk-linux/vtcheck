import requests
import time
import sys
import os


API_KEY = ''  # Replace with your VirusTotal API key
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
        print(response.text)
        return response.json()
    else:
        print(f"Error retrieving results: {response.status_code} {response.text}")
        return None

def check_suspicious_content(file_path):
    analysis_id = submit_file(file_path)
    if not analysis_id:
        print("Failed to submit file.")
        return
    
    print("File submitted successfully. Waiting for analysis results...")
    time.sleep(10)  # Wait for analysis to complete, adjust timing as necessary

    results = get_analysis_results(analysis_id)
    if not results:
        print("Failed to retrieve results.")
        return

    # Process general scan results
    malicious_count = 0
    total_engines = 0
    if 'attributes' in results['data'] and 'results' in results['data']['attributes']:
        for engine, result in results['data']['attributes']['results'].items():
            total_engines += 1
            if result['category'] == 'malicious':
                malicious_count += 1

    if malicious_count > 0:
        print(f"Suspicious content found in general scan! {malicious_count} out of {total_engines} engines flagged the file as malicious.")
    else:
        print("No suspicious content found in general scan.")

    # Check sandbox results
    if 'attributes' in results['data'] and 'sandbox_verdicts' in results['data']['attributes']:
        sandbox_results = results['data']['attributes']['sandbox_verdicts']
        if sandbox_results:
            for sandbox in sandbox_results:
                if sandbox['verdict'] == 'malicious':
                    print(f"Sandbox analysis flagged the file as malicious by {sandbox['sandbox_name']}.")
                else:
                    print(f"Sandbox analysis by {sandbox['sandbox_name']} did not flag the file as malicious.")
        else:
            print("No sandbox analysis results available.")
    else:
        print("No sandbox analysis available.")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: python vtcheck.py <file to check>" + os.linesep)
        exit(-1)
    check_suspicious_content(sys.argv[1])
