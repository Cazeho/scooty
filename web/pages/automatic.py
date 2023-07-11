import streamlit as st
import os
import tempfile
import json
import requests

st.set_page_config(page_title="automatic",  page_icon="🧭")
st.sidebar.header("automatic")

st.title("Automatic analysis VT & Triage sandbox")







def vt_analyse(file_hash):
    url = f"https://www.virustotal.com/ui/files/{file_hash}"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
        "X-Tool": "vt-ui-main",
        "X-VT-Anti-Abuse-Header": "MTA3OTM2NjUwMjctWkc5dWRDQmlaU0JsZG1scy0xNjMxMTE3NzQyLjY1",
        "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
    }
    data=requests.get(url, headers=headers).json()
    return data



def read_temp_files():
    temp_dir_name = 'sample'
    
    temp_dir = os.path.join(tempfile.gettempdir(), temp_dir_name)
    
    if not os.path.exists(temp_dir):
        print("Temporary directory does not exist:", temp_dir)
        return
    
    print("Temporary directory:", temp_dir)
    

    file_list = os.listdir(temp_dir)
    
    for file_name in file_list:
        file_path = os.path.join(temp_dir, file_name)
        with open(file_path, 'r') as file:
            data = file.read()
            st.write("Data:", data)
            st.write(vt_analyse(data))
        
        os.remove(file_path)

read_temp_files()
