import requests
import json
import hashlib
import argparse
import sys


BUF_SIZE = 65536  # read in 64kb chunks

session = requests.Session()
session.headers = {'X-Apikey': ''}

data={}
VT_API_ENDPOINT = 'https://www.virustotal.com/api/v3/files'


def get_hash(file, hash_type):
    if hash_type == 'md5':
        hash_obj = hashlib.md5()
    elif hash_type == 'sha256':
        hash_obj = hashlib.sha256()
    else:
        raise ValueError("Invalid hash type. Choose either 'md5' or 'sha256'.")

    with open(file, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            hash_obj.update(data)

    return hash_obj.hexdigest()


def send_hash(hash):
    VT_API_SEARCH_HASH=f'https://www.virustotal.com/api/v3/search?query={hash}'
    response = session.get(VT_API_SEARCH_HASH)
    if response.status_code == 200 and len(response.json()['data']) > 0:
        return response.json()
    else:
        return "not found"
    
def send_file(file):
        attachment_data = open(file,'rb')
        files = {'file': (file, attachment_data)}
        response = requests.post(VT_API_ENDPOINT, files=files,headers=session.headers)
        scan_id = response.json()['data']['id']
        VT_API_REPORT_ENDPOINT = f'https://www.virustotal.com/api/v3/analyses/{scan_id}'
        response = requests.get(VT_API_REPORT_ENDPOINT, headers=session.headers)
        res=response.json()["url"]=f"https://www.virustotal.com/gui/file/{response.json()['meta']['file_info']['sha256']}"
        data["analyse"]=response.json()
        data["link"]=res
        return data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Tool for SOC analyst')
    parser.add_argument('--web',action='store_true', help='use web interface',default=None)
    parser.add_argument('filename', help='The name of the file to hash.')
    parser.add_argument('--hash', choices=['md5', 'sha256'], default='sha256', help='The type of hash to use.')
    parser.add_argument('--sendhash', action='store_true', help='send hash to virustotal')
    parser.add_argument('--sendfile', help='send file to virustotal')

    args = parser.parse_args()

    try:
        if args.web and args.filename =="idle":
            hash_result = ""
        """
        hash_result = get_hash(args.filename, args.hash)
        print(f'The {args.hash} hash of the file is: {hash_result}')
        
        if args.sendhash:
            print('Sending the hash to VirusTotal...')
            response = send_hash(hash_result)
            print('Response from VirusTotal:')
            print(response)

        if args.sendfile:
            print('Sending the file to VirusTotal...')
            response = send_file(args.filename)
            print('Response from VirusTotal:')
            print(response)
           """ 
    except Exception as e:
        print(e)
        sys.exit(1)