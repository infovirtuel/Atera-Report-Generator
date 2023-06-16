# Atera Report Generator Version 1.5.4
![banner2](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/001f8192-e602-4bee-b0cc-3ed534af82f9)


# Index

[News](#News)

[Feature Summary](#Feature-Summary)

[Roadmap](#Roadmap)

[UI Previews](#UI-Previews)

[CLI User Guide](#CLI-GUIDE)

[Build from Source](#BUILD-FROM-SOURCE)

# News

ARG 1.5.4.2 Revision 2 is out!
Tons of things have been fixed and changed in the backend to make the experience more user friendly, the reports cleaner, and much more.

ARG has a brand new User interface that looks and feels modern on every OS Type.

Got a new logo banner for the UI to save on screen space.

IP Geolocalisation is here! The feature is entirely optional. It can query the public geolocalisation API of your choice.

The reports are now easier to read thanks to data formatting and harmonizxation of the order of rows between pdf/ui/csv/teams.

Excel (xlsx) Reports can now be generated automatically.

# Feature Summary:

Modern UI with a light/dark theme.

Advanced Reporting through multiple parameters and multiple search values

Create spreadsheet Reports in csv and xlsx

Create PDF Reports for your customers.

Send Report to a Microsoft Teams channel

Quick glance at your results with the UI report.

SNMP/HTTP/TCP/Agents Device Report

Email Reports by Encrypted SMTP (csv, xlsx, pdf attachments)

Encrypted sensitive informations in system keyring

Operating System End of life date/status in CSV Report.

IP Geolocalisation and ISP reporting

Scheduled reports through the task scheduler or cronjobs


# Roadmap
## 1.5.4.x - Steamed Hams

### BACKEND

:x: Reduce the amount of API calls and faster reporting with caching optional feature

:x: function to choose cache deprecation time 

:white_check_mark: Fix to LAN IP search in Agents Reports

:white_check_mark: Move EOL function to extract_device_information

:white_check_mark: harmonisation of report rows and labels for teams/pdf/ui/csv

### SECURITY

:x: Password-derived encryption for the API key

### UI

:white_check_mark: Dynamically resize the UI for small resolution screens

:white_check_mark: Individual tabs for General/Email/SMTP configuration menu

:white_check_mark: Each report type (device,snmp,http...) in a tab of the main menu

:white_check_mark: Cleaner and more modern UI on Windows.

### FEATURES

:white_check_mark: Device Geolocation & ISP

:white_check_mark: OnlineOnly/EOL/Geolocation options can be saved in configuration menu

:white_check_mark: EOL function available to Teams/PDF/UI reports

:white_check_mark: Teams reports in CLI for all types

:x: CPU release date for Intel Processors

:x: Simple Regular expressions support in search (*,!,>,<)

:x: Menu to create new scheduled tasks from the UI.

:x: FreeBSD support

:x: Linux ARM & Raspberry Pi Support

:x: MacOS Apple Sillicon Support

## V1.5.5.x - Skinners

### FEATURES

:x: Device statistics per OS Version, WAN IP, company, etc.)

:x: PDF/UI pie charts

:x: POST custom value fields to searched devices

:x: Pretty & customizable PDF Reports


## Feature wishlist & ideas

### These features might get integrated at any time or never.

Spinoffs of ARG for other popular RMMs

Import/export TCP/HTTP devices from and to Freshping

Atera API python (pip) module

Customer Contract/information reporting

Option to send email to primary contact per customer

Better loading animation for UI

Web UI (Mobile Friendly) 

SNMP/HTTP/TCP/Generic device creation menu

Warranty reports for Dell, Lenovo and HP

# UI Preview:
![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/6a45410e-d7e6-4313-8fae-b5e6c6f29515)

# CLI GUIDE

## EXAMPLES: 

'.\Atera Report Generator.exe' --cli --snmp --devicename forti --csv

'.\Atera Report Generator.exe' --cli --agents --ostype server --customername example --csv --pdf --email


## REFERENCE SHEET:

--cli
      --agents
              #SEARCH-OPTIONS
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

                                    #REPORT-OPTIONS
                                    --csv
                                    --pdf
                                    --email
                                    --teams



---------------------------------------------------------------      
 --cli
      --snmp
              #SEARCH-OPTIONS
              --devicename VALUE
              --deviceid VALUE
              --hostname VALUE
              --customername VALUE
              --type VALUE
                                    #REPORT-OPTIONS
                                    --csv
                                    --pdf
                                    --email
                                    --teams
      
---------------------------------------------------------------   
 --cli
      --http
              #SEARCH-OPTIONS
              --devicename VALUE
              --deviceid VALUE
              --url VALUE
              --customername VALUE
              --pattern VALUE
                                    #REPORT-OPTIONS
                                    --csv
                                    --pdf
                                    --email
                                    --teams
      
---------------------------------------------------------------
 --cli
      --tcp
              #SEARCH-OPTIONS
              --devicename VALUE
              --deviceid VALUE
              --hostname VALUE
              --customername VALUE
              --portnumber VALUE
                                    #REPORT-OPTIONS
                                    --csv
                                    --pdf
                                    --email
                                    --teams
      
---------------------------------------------------------------






--cli   
     --configure
                  #GENERAL-OPTIONS
                  --apikey VALUE   
                  --teamswebhook VALUE 
                  --geoprovider VALUE
                  --geolocation VALUE
                  --eol VALUE
                   #SMTP-OPTIONS
                  --password VALUE 
                  --username VALUE
                  --port VALUE 
                  --server VALUE 
                  --starttls VALUE 
                  --ssl VALUE 
                  --password VALUE 
                  #EMAIL-OPTIONS
                  --sender VALUE  
                  --recipient VALUE
                  --subject VALUE
                  --body VALUE
              


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

tqdm
