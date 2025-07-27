import json 
import requests
import os
import hashlib
from dotenv import load_dotenv
load_dotenv()
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
    API_KEY = os.getenv("API_KEY")  # enter your api key in .env file
    if not API_KEY:
        print("Error : API_KEY not found in .env file check .env file")
    else:
        print(f"API key loaded {API_KEY[:4]}....{API_KEY[-4:]}")
        scanner = Virustotalscanner(API_KEY)
        FILE_PATH = os.getenv("FILE_PATH")  # Path to the file
        # Remove any quotes from FILE_PATH
        if FILE_PATH:
            FILE_PATH = FILE_PATH.strip('"').strip("'").strip()
        # Check if file exists, else prompt user
        while not FILE_PATH or not os.path.isfile(FILE_PATH):
            print(f"Error: FILE_PATH '{FILE_PATH}' is not set or file does not exist.")
            FILE_PATH = input("Please enter a valid file path to scan: ").strip('"').strip("'").strip()
    calculate_hash_of_file=scanner.get_file_256(FILE_PATH)
    hash_result=scanner.get_report_file(calculate_hash_of_file)
    if hash_result and hash_result.get("data",{}):
        print(f"This file is already in Virustotal Database")
        scanner.pretty_print_report(hash_result)
        # here make such that it calls for another function report and then print that report
        # that function will just print the pretty output of the report not just a basic json but good
    else:
        result = scanner.upload_file(FILE_PATH)
        if result:
            analysis_id = result.get("data", {}).get("id")
            if analysis_id:
                analysis_result = scanner.analysis_status(analysis_id)
                analysis_status=analysis_result.get('data', {}).get('attributes',{}).get('status',{})
                print(f"Your status is {analysis_status}")  
        else:
            print("Could not retrieve analysis ID from upload result.")


    
    # test=scanner.get_report(analysis_id="OTlmYjE2M2NlMzVmNDg5YjJkYTgzZmZiZGYxOTY3MmM6MTc1MzExODIzNQ==")
    # print(json.dumps(test, indent=4))