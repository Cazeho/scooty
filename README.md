# scooty (In progress)

[![Generic badge](https://img.shields.io/badge/Made%20with-Python-blue.svg?style=flat-square)](https://github.com/Cazeho/scooty)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-green.svg?style=flat-square)](https://github.com/Cazeho/scooty)
[![GitHub contributors](https://img.shields.io/github/contributors/Cazeho/scooty.svg?style=flat-square)](https://github.com/Cazeho/scooty/graphs/contributors/)
[![Generic badge](https://img.shields.io/badge/Built%20For-SOC%20Analyst's-olive.svg?style=flat-square)](https://GitHub.com/theresafewconors/sooty)
![Docker](https://img.shields.io/badge/Docker-Supported-blue)


# Overview

Scooty is a tool developed with the task of aiding SOC analysts with automating part of their workflow. One of the goals of Scooty is to perform as many of the routine checks as possible, allowing the analyst more time to spend on deeper analysis within the same time-frame. Details for many of Scooty's features can be found below.

### Platform

Linux & Windows & docker


## Contents
 - [Current Features](#feature--integrate-tools)
 - [Requirements & Installation](#requirements-and-installation)
 - [Usage](#usage)
 - [Development](#development)
 - [Changelog](#changelog)


### feature & integrate tools

- file type (*)
- hash sha256, md5, sha1 (*)
- send hash to VT (*)
- send file to VT (*)
- pescan / clamscan / capa ???
- analyse .doc => oleid, oleobj
- analyse .pdf => peepdf, pdf-parser
- regex onlist url, ip
- event log parser => python-evtx
- linux log parser => ssh, apache, nginx
- email analysis => headers
- send file to triage sandbox (*)
- web inferface (*)

### requirements and installation

#### install on linux

```curl -s https://raw.githubusercontent.com/Cazeho/scooty/main/install.sh | bash```

#### You need to get VT & Tria.ge API Key

```nano /opt/scooty/web/config.yaml```

### usage

#### Get web interface

```python3 scooty.py idle --web```

#### Get web interface with filename analysis

```python3 scooty.py example.txt --web```

#### Get hash and file type

```python3 scooty.py example.txt```
<br>
```python3 scooty.py example.txt --hash md5```

#### Send file hash to Virustotal for analysis

```python3 scooty.py example.txt --sendhash```

#### Send file to Virustotal for analysis

```python3 scooty.py example.txt --sendfile```


