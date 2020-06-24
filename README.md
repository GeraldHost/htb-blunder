# HTB Blunder

## About
Python script that automates a back-connect shell on the HackTheBox machine **Blunder**.

Exploits a vulnerability in the Bludit CMS:
https://github.com/bludit/bludit/issues/1081

## Requirements
Requires netcat to be installed on your system and installed to your $PATH as **nc**

## Usage
Specify the host and port you wish to listen on:

`htb-blunder.py {LHOST} {LPORT}`