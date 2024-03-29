#! /usr/bin/python3

import requests
import json
import hashlib
import argparse
import sys
import mimetypes
import subprocess
import os
import yaml
import signal

import tempfile

###########################################


def create_temp_file(sample_path):
    temp_dir = os.path.join(tempfile.gettempdir(), "sample")
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)

    temp_file = tempfile.mktemp(dir=temp_dir)
    with open(temp_file, 'w') as file:
        file.write(sample_path)


def delete_temp_file():
    pass




###########################################



with open('web/config.yaml', 'r') as f:
    config = yaml.safe_load(f)


class Subprocess:
    def __init__(self, command):
        self.command = command
        self.process = None

    def run(self):
        if sys.platform.startswith('win'):
            self.process = subprocess.Popen(self.command, shell=True)
        else:
            self.process = subprocess.Popen(self.command, shell=True, preexec_fn=os.setsid)
        
        try:
            self.process.wait()
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        if self.process:
            if sys.platform.startswith('win'):
                self.process.terminate()
            else:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)

BUF_SIZE = 65536

session = requests.Session()
session.headers = {'X-Apikey': config['virustotal']['api_key']}

data={}
VT_API_ENDPOINT = 'https://www.virustotal.com/api/v3/files'


def get_hash(file, hash_type):
    if hash_type == 'md5':
        hash_obj = hashlib.md5()
    elif hash_type == 'sha256':
        hash_obj = hashlib.sha256()
    elif hash_type == 'sha1':
        hash_obj = hashlib.sha1()
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
    parser.add_argument('--web',action='store_true', help='use web interface')
    parser.add_argument('filename', help='The name of the file to hash.')
    parser.add_argument('--hash', choices=['md5', 'sha256',"sha1"], default='sha256', help='The type of hash to use.')
    parser.add_argument('--sendhash', action='store_true', help='send hash to virustotal')
    parser.add_argument('--sendfile', action='store_true',help='send file to virustotal')

    args = parser.parse_args()

    try:
        if args.web and args.filename =="idle":
            s = Subprocess("streamlit run ./web/app.py")
            s.run()

        elif  args.web and args.filename !="idle":
            #file_path = os.path.abspath(args.filename)
            #print(file_path)
            hash=get_hash(args.filename, args.hash)
            create_temp_file(hash)
            s = Subprocess("streamlit run ./web/pages/automatic.py")
            s.run()

        else:
            hash_result = get_hash(args.filename, args.hash)
            mimetype = mimetypes.guess_type(args.filename)
            print(f"The file type is: {mimetype[0]}")
            print(f'The {args.hash} hash : {hash_result}')
            
            if args.sendhash:
                print('Scanning the hash to VirusTotal...')
                response = send_hash(hash_result)
                print('Response from VirusTotal:')
                print(response)
                
            if args.sendfile:
                print('Scanning the file to VirusTotal...')
                response = send_file(args.filename)
                print('Response from VirusTotal:')
                print(response)
            
    except Exception as e:
        print(e)
        sys.exit(1)

