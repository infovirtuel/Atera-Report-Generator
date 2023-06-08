# Atera Report Generator Version 1.5.3.5
![logo](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/d1613878-09f1-49d7-a207-8c77a85c4cdf)

# Index
[Benefits](#Benefits-to-use-the-Atera-Report-Generator)

[Feature Summary](#Feature-Summary)

[Latest Features](#Latest-Features)

[UI Previews](#UI-Previews)

[Report Options](#Report-Options)

[CLI User Guide](#CLI)

[Build from Source](#BUILD-FROM-SOURCE)

# Benefits to use the Atera Report Generator

Simple interface that can be used by both begginers and advanced users

Scheduled reports by email or sent to network share or local path

Secure integration of Atera with a local environnement

Advanced reports for every customer tiers in less than 15sec*. 

Send email reports to your clients about the health of their devices

Monitor which device requires to be replaced depending on CPU Age and OS version (work in progress)

Desktop Search Engine for Atera

Open-Source and free to use for Atera Customers

Get the End of life status of your devices

* 8-10 second search estimated for 16 pages of 50 pages. EOL option adds another 5-10 sec


#  Latest Features

Encrypted SMTP (StartTLS/SSL)

CLI Interface (Scheduled Agents and SNMP reports through the Task Scheduler on windows)

Operating System End of life included in CSV Report (Optional)

Multiple search values per parameters separated by a comma (,) ex. OS Version: 2012,2019


# Feature Summary:

Advanced Reporting through multiple parameters and multiple search values

Create CSV Reports

Microsoft Teams Outputs (Experimental) 

UI Reports

SNMP Device Report

PDF Reports for regular devices and SNMP Devices

Email Reports by Encrypted SMTP (csv, pdf attachments) for regular devices and SNMP Devices

Configuration menu for Email, SMTP and API key/Webhook/local path

Encrypted sensitive informations in system keyring

Operating System End of life date/status in CSV Report.

# Work in Progress for 1.5.3.x - Aurora Borealis

## FEATURES
:white_check_mark: Operating System End of Life report option

:white_check_mark: Comma Separated Search

:white_check_mark: CLI Interface

:x: free disk space in csv/pdf/UI output

## BACKEND

:x: move config.ini to ''%appdata%/Local/Atera Report Generator'' on windows build

:x: New installer to create start menu/desktop shortcuts

:x: remove the search options from searchops.ini

:white_check_mark: SMTP Security Enhancements (SSL and certificate verification)

:x: unified output function to simplify adding new output methods

:x: EOL report in a separate function instead of being built in fetch_devices_informations



## CLI
      
:x: simple loading animation in CLI

:x: CLI Enhancements

## UI

:x: Combine all the output popups into a single one before UI display

:x: Menu to create new scheduled tasks from the UI.

# Roadmap for 1.5.4.x - Steamed Hams

## BACKEND

Reduce the anount of API calls and faster reporting with caching optional feature

function to choose cache deprecation time 

Cleanup of redundant functions to make the integration of http/generic/tcp devices easier

Split functions in different py files (compiled in one executable)

## SECURITY

Password-derived encryption for API key in config.ini

## UI

Individual tabs for General/Email/SMTP configuration menu

## SNMP MODULE:

Advanced Reporting (similar to agents)

More search fields and  output information


# Roadmap for V1.6.x.x - Skinners

## FEATURE:

:x: Device statistics per OS Version, WAN IP, company, etc.)

:x: TCP/GENERIC/HTTP Device Reporting

:x: PDF/UI pie charts

:x: POST custom value fields to searched devices

## UI:

:x: Each report type (device,snmp,http...) in a tab of the main menu

:x: Cleaner UI

# Feature wishlist

Import/export TCP/HTTP devices from and to Freshping

Atera API python (pip) module

Customer Contract/information reporting

Option to send email to primary contact per customer

Better loading animation for UI

Web UI (Mobile Friendly) 

CSV/PDF output to teams

SNMP/HTTP/TCP/Generic device creation menu

Warranty reports for Dell, Lenovo and HP

CPU Age reports

and more..

# UI Previews:

Main Menu:

![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/7c666b6c-4ed0-464f-b61b-3b42650671af)


SNMP Reports:

![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/3db98a0c-1b93-4a9a-b0b8-c2c668014016)


Configuration Menu:

![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/f975b265-4209-4a2d-abe8-4535e50efb02)



# Report Options

Agent Name

Agent ID

IP Address

Machine Name

Customer Name

OS Type (Server, Work Station, Domain Controller)

Vendor (Dell Inc. , HP, LENOVO, Microsoft Corporation)

Serial Number

WAN IP Address

Domain Name

Currently logged in user

PC/Server Model (Exemple: Latitude 3510)

Processor (i5,i7,Xeon,etc)

Processor Core Amount 

OS Version

Online Only Devices

# CLI
Configuration needs to be done through the UI before using the CLI as the API Key is stored in the keyring.

On a headless server, you can import the required values (API Key, SMTP Password, Webhook URL) in the system keyring

All the other configuration options are in the config.ini file

devicename, customername, etc. on the agents report can be combined to do refined reports

SNMP report supports ONLY ONE option

SNMP and AGENTS cannot be combined

EXAMPLES: 

'.\Atera Report Generator.exe' --cli --snmp --snmpdevicename forti --csv

'.\Atera Report Generator.exe' --cli --agents --ostype server --customername example --csv --pdf --email


REFERENCE SHEET:

Atera Report Generator.exe 
--cli

      --csv
      --pdf
      --email
      --onlineonly
      --eolreport

                  --agents
                            --devicename VALUE
                            --customername VALUE
                            --lanip VALUE
                            --ostype VALUE
                            --serialnumber VALUE
                            --vendor VALUE
                            --wanip VALUE
                            --domain VALUE
                            --username VALUE
                            --model VALUE
                            --processor VALUE
                            --cores VALUE
                            --os VALUE
      
                  --snmp 
                            --snmpdevicename VALUE
                            --snmpdeviceid VALUE
                            --snmphostname VALUE
                            --snmpcustomername VALUE
                            --snmptype VALUE

# BUILD FROM SOURCE

Copy the entire git repo locally

pip install pyinstaller

pyinstaller --onefile --icon=arg.png --add-data "images;images" "Atera Report Generator.py"

import and install the following modules if necessary:

requests

json

csv

configparser

datetime

tkinter

PIL

os

webbrowser

itertools

smtplib

reportlab

keyring

sys

ssl

ast

argparse



