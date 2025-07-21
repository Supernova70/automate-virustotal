import json 
import requests
import os
from dotenv import load_dotenv
load_dotenv()
# url = "https://www.virustotal.com/api/v3/files"
# files = {}
# headers = {
#     "accept": "application/json",
#     "content-type": "multipart/form-data"
# }

# response = requests.post(url, headers=headers)

# print(response.text)


# def upload_file(self)
    

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
if __name__ == "__main__":
    API_KEY = os.getenv("API_KEY")  # enter your api key in .env file
    if not API_KEY:
        print("Error : API_KEY not found in .env file check .env file")
    else:
        print(f"API key loaded {API_KEY[:4]}....{API_KEY[-4:]}")
        scanner = Virustotalscanner(API_KEY)
    FILE_PATH = "enter your file path "  # Replace with the path to the file
    result = scanner.upload_file(FILE_PATH)
    if result:
        analysis_id = result.get("data", {}).get("id")
        if analysis_id:
            analysis_result = scanner.analysis_status(analysis_id)
            print(json.dumps(analysis_result, indent=4))
        else:
            print("Could not retrieve analysis ID from upload result.")
