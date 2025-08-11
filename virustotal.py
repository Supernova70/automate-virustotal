def send_webhook(webhook_url, payload):
    """Send a JSON payload to a webhook URL via HTTP POST."""
    try:
        response = requests.post(webhook_url, json=payload, headers={"Content-Type": "application/json"})
        response.raise_for_status()
        print(f"Webhook sent successfully: {response.status_code}")
    except requests.RequestException as e:
        print(f"Failed to send webhook: {e}")

import json 
import requests
import os
import hashlib
from dotenv import load_dotenv
import base64
load_dotenv()
import argparse
from pathlib import Path
# url = "https://www.virustotal.com/api/v3/files"
# files = {}
# headers = {
#     "accept": "application/json",
#     "content-type": "multipart/form-data"
# }

class Virustotalscanner:
    def __init__(self,api_key):
        self.api_key=api_key
        self.base_url="https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
    
    def scan_url(self,scan_url):
        url=f"{self.base_url}/urls"
        payload = { "url": scan_url }
        try:
            response=requests.post(url,data=payload,headers=self.headers)
            response.raise_for_status()
            result=response.json()
            return result
        except requests.RequestException as e:
            print(f"Got some error {e}")
            return None


    def upload_file(self,file_path):
        file_size= os.path.getsize(file_path)
        max_upload_size=32*1024*1024  # as we can directly upload only 32 mb 
    # for more than 32 first we have to create a try catch and then there is different 
    # api for upload file which is more than 32 mb 
        try:
            if file_size<= max_upload_size:
                url=f"{self.base_url}/files"
                with open (file_path,"rb") as f:
                    files = {"file":(os.path.basename(file_path),f)}   
                    response= requests.post(url,headers=self.headers,files=files)    
            else:
                url=f"{self.base_url}/files/upload_url"    
                response=requests.get(url,headers=self.headers)
                response.raise_for_status()
                upload_url=response.json().get("data")
                print(upload_url)
                with open(file_path,"rb") as f:
                    files={"file":(os.path.basename(file_path),f)}
                    # Create a new header without the x-apikey for the upload_url
                    upload_headers = self.headers.copy()
                    upload_headers.pop("x-apikey", None)
                    response=requests.post(upload_url,headers=upload_headers,files=files)
            response.raise_for_status()
            result=response.json()
            analysis_id =result.get("data",{}).get("id")
            # print(analysis_id)
            if analysis_id:
                print(f"File uploaded successfully. Analysis ID: {analysis_id}")
                return result
            else:
                print("Error: No analysis ID returned.")
                return None
                
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error occurred: {http_err}")
            return None
        except requests.exceptions.RequestException as req_err:
            print(f"Request error occurred: {req_err}")
            return None
        except FileNotFoundError:
            print(f"Error: File '{file_path}' not found.")
            return None
        except Exception as e:
            print(f"Unexpected error: {e}")
            return None


    def analysis_status(self,analysis_id):
        url=f"{self.base_url}/analyses/{analysis_id}"
        try:
            response=requests.get(url,headers=self.headers)
            response.raise_for_status()
            data=response.json()
            return data
        except requests.RequestException as e:
            print(f"Error while checking analyses {e}")
            return None


    def get_report(self,analysis_id):
        url=f"{self.base_url}/analyses/{analysis_id}"
        try:
            response=requests.get(url,headers=self.headers)
            response.raise_for_status()
            data=response.json()
            status=data.get("data", {}).get("attributes", {}).get("status")
            if status=="completed":
                print("Analyses completed sucessfully ")
                return data
            elif status=="queued":
                print("Analysis is still queued check after few time again ")
            elif status=="running":
                print("Analyses is still running please wait")
            else:
                print(f"Analysis status {status}")
                return data
        except requests.RequestException as e:
            print(f"Error while getting report {e}")
            return None
    @staticmethod
    def get_file_256(file_path):
        sha256=hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                 sha256.update(chunk)
        return sha256.hexdigest()
    


    def pretty_print_report(self, report_json):
        """ Prints a readable summary of the VirusTotal analysis report. """
        if not report_json or "data" not in report_json:
            print("No report data available.")
            return

        data = report_json["data"]
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        results = attributes.get("last_analysis_results", {})
        file_info = {
            "Name": attributes.get("meaningful_name", "N/A"),
            "SHA256": attributes.get("sha256", "N/A"),
            "MD5": attributes.get("md5", "N/A"),
            "Type": attributes.get("type_description", "N/A"),
            "Size": attributes.get("size", "N/A"),
        }

        print("\n=== File Information ===")
        for k, v in file_info.items():
            print(f"{k}: {v}")

        print("\n=== Detection Stats ===")
        for k, v in stats.items():
            print(f"{k.capitalize()}: {v}")

        print("\n=== Major Engine Results ===")
        major_engines = ["Kaspersky", "BitDefender", "ESET-NOD32", "Microsoft", "McAfee", "Symantec", "Avast", "AVG"]
        for engine in major_engines:
            engine_result = results.get(engine)
            if engine_result:
                print(f"{engine}: {engine_result.get('category', 'N/A')} ({engine_result.get('result', 'Clean')})")
            else:
                print(f"{engine}: No result")

        print("\n=== All Detections ===")
        detected = {k: v for k, v in results.items() if v.get("category") == "malicious"}
        if detected:
            for engine, result in detected.items():
                print(f"{engine}: {result.get('result', 'malicious')}")
        else:
            print("No malicious detections found.")

        print("\n=== Scan Date ===")
        scan_date = attributes.get("last_analysis_date", None)
        if scan_date:
            from datetime import datetime
            try:
                readable_date = datetime.fromtimestamp(int(scan_date)).strftime('%Y-%m-%d %H:%M:%S')
                print(readable_date)
            except Exception:
                print(scan_date)
        else:
            print("N/A")




    def get_report_file(self,file_hash):
        """
        This will give the report based on hash of the file 
        """
        url=f"{self.base_url}/files/{file_hash}"
        try:
            response=requests.get(url,headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error while getting report by hash {e}")
            return None




if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VirusTotal CLI Scanner")
    parser.add_argument('--apikey', type=str, default=os.getenv("API_KEY"), help='VirusTotal API key (or set API_KEY in .env)')
    subparsers = parser.add_subparsers(dest='command', required=True, help='Sub-command to run')

    # Scan URL
    parser_url = subparsers.add_parser('scan-url', help='Scan a URL')
    parser_url.add_argument('--url', type=str, required=True, help='URL to scan')

    # Scan File
    parser_file = subparsers.add_parser('scan-file', help='Scan a file')
    parser_file.add_argument('--file', type=str, required=True, help='Path to file to scan')

    # Get File Report by Hash
    parser_hash = subparsers.add_parser('get-file-report', help='Get file report by hash')
    parser_hash.add_argument('--file', type=str, required=True, help='Path to file to get hash and report')

    # Get Report by Analysis ID
    parser_analysis = subparsers.add_parser('get-analysis-report', help='Get report by analysis ID')
    parser_analysis.add_argument('--id', type=str, required=True, help='Analysis ID')


    # Webhook sender CLI
    parser_webhook = subparsers.add_parser('send-webhook', help='Send scan result to a webhook URL')
    parser_webhook.add_argument('--file', type=str, required=True, help='Path to file to scan and send result')
    parser_webhook.add_argument('--webhook-url', type=str, required=False, default=os.getenv("WEBHOOK_URL"), help='Webhook URL to send the scan result (or set WEBHOOK_URL in .env)')

    args = parser.parse_args()

    if not args.apikey:
        print("Error: API key not provided. Use --apikey or set API_KEY in .env file.")
        exit(1)
    scanner = Virustotalscanner(args.apikey)

    if args.command == 'scan-url':
        result = scanner.scan_url(args.url)
        print(json.dumps(result, indent=4))

    elif args.command == 'scan-file':
        file_path = args.file
        if not os.path.isfile(file_path):
            print(f"Error: File '{file_path}' does not exist.")
            exit(1)
        calculate_hash_of_file = scanner.get_file_256(file_path)
        hash_result = scanner.get_report_file(calculate_hash_of_file)
        if hash_result and hash_result.get("data", {}):
            print(f"This file is already in VirusTotal Database")
            scanner.pretty_print_report(hash_result)
        else:
            result = scanner.upload_file(file_path)
            if result:
                analysis_id = result.get("data", {}).get("id")
                if analysis_id:
                    analysis_result = scanner.analysis_status(analysis_id)
                    analysis_status = analysis_result.get('data', {}).get('attributes', {}).get('status', {})
                    print(f"Your status is {analysis_status}")
            else:
                print("Could not retrieve analysis ID from upload result.")

    elif args.command == 'get-file-report':
        file_path = args.file
        if not os.path.isfile(file_path):
            print(f"Error: File '{file_path}' does not exist.")
            exit(1)
        file_hash = scanner.get_file_256(file_path)
        result = scanner.get_report_file(file_hash)
        print(json.dumps(result, indent=4))

    elif args.command == 'get-analysis-report':
        analysis_id = args.id
        result = scanner.get_report(analysis_id)
        if result:
            scanner.pretty_print_report(result)
        else:
            print("Could not retrieve report for the given analysis ID.")

    elif args.command == 'send-webhook':
        file_path = args.file
        webhook_url = args.webhook_url
        if not webhook_url:
            print("Error: Webhook URL not provided. Use --webhook-url or set WEBHOOK_URL in .env file.")
            exit(1)
        if not os.path.isfile(file_path):
            print(f"Error: File '{file_path}' does not exist.")
            exit(1)
        file_hash = scanner.get_file_256(file_path)
        result = scanner.get_report_file(file_hash)
        if not result or not result.get("data", {}):
            print("File not found in VirusTotal. Uploading and scanning...")
            result = scanner.upload_file(file_path)
            if not result:
                print("Failed to upload and scan file.")
                exit(1)
        # Send the full report as JSON
        send_webhook(webhook_url, result)


    
    # test=scanner.get_report(analysis_id="OTlmYjE2M2NlMzVmNDg5YjJkYTgzZmZiZGYxOTY3MmM6MTc1MzExODIzNQ==")
    # print(json.dumps(test, indent=4))