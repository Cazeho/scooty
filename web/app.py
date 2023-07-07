import streamlit as st
import time
import requests as rq
from io import BytesIO
import time
from typing import Optional
import json
import yaml

with open('config.yaml', 'r') as f:
    config = yaml.safe_load(f)


st.set_page_config(page_title="home",  page_icon="🧭")
st.sidebar.header("Home")

st.title("Scooty : Couteau Suisse de l'analyste SOC")

st.title("Virustotal")

ioc= st.text_input("Enter your IOC (@IP, URL, FQDN et Hash File)")


api_key=config['triage']['api_key']

def auth_triage(api_key):
    header = {'Authorization': 'Bearer ' + api_key}
    return header




class Triage():
    def __init__(self, api: str):
        self.base_url = "https://tria.ge/api/v0/samples"
        self.api = api
        
    def analyse_url(self,url):
        data = {'url': url}
        response = rq.post(self.base_url, headers=self.api, data=data)
        return response.json()['id'] 
    
    def display_sandbox(self,id):
        st.write(f"https://tria.ge/{id}/behavioral1")
        
    def result_analysis(self,id):
        url = f'https://tria.ge/api/v0/samples/{id}/overview.json'
        response = rq.get(url, headers=self.api)
        return response.json()
    

    def send_file_direct(self,filepath):
        files = {'file': open(filepath, 'rb')}
        response = rq.post(self.base_url, headers=self.api, files=files)
        return response.json()['id'] 
    
    def send_file(self,filepath):
        files = {'file': filepath}
        response = rq.post(self.base_url, headers=self.api, files=files)
        return response.json()['id'] 



st.title("Triage sandbox")
st.subheader("Upload file")
up = st.file_uploader(
"Drag and Drop or Click to Upload", accept_multiple_files=False
)
if up is not None:
    st.write(up)
    triage=Triage(auth_triage(api_key))
    id=triage.send_file(up)
    triage.display_sandbox(id)
    while True:
        triage.result_analysis(id)
        time.sleep(5)
        if "message" not in triage.result_analysis(id):
            st.write(json.dumps(triage.result_analysis(id), indent=4))
            break



st.subheader("url_file")

with st.form(key='url'):
    st.write("submit url")
    u=st.text_input("url")
    submit = st.form_submit_button(label='Url')

if submit:
    triage=Triage(auth_triage(api_key))
    id=triage.analyse_url(u)
    triage.display_sandbox(id)
    while True:
        triage.result_analysis(id)
        time.sleep(5)
        if "message" not in triage.result_analysis(id):
            st.write(json.dumps(triage.result_analysis(id), indent=4))
            break
