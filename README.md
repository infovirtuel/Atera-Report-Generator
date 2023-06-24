# Atera Report Generator Version 1.5.4
![banner3](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/49b9aba7-ccd6-447e-9f90-c202197292b3)



# Index

[News](#News)

[Feature Summary](#Feature-Summary)

[Roadmap](#Roadmap)

[UI Previews](#UI-Previews)

[CLI User Guide](#CLI-GUIDE)

[Build from Source](#BUILD-FROM-SOURCE)

# News

## Web Edition
The Web version of ARG is (almost) ready for beta release.
it's much lighter than the UI version and can be considered complimentary to the standard release.
What doesn't work yet: snmp/tcp/http reports & email/smtp config menu options

## 1.5.4.x

ARG 1.5.4.4 is out!

PDF Reports are now easier on the eye and fit the overall Atera visual style.

critical bugs have been fixed

ARG now has an optional caching feature in the misc. menu,
It's awesome and is a must-have for regular power users.

Also please check out the OS End of life & geolocation features!

## 1.5.5.x

I will split the linux build and the MacOS build from the windows build in ARG 1.5.5.x.

The windows build will stay the main focus of developement.

The linux build will focus on the web version, cli and docker, while the backend will remain compatible with the main Windows Build.

The macOS build will only retain the GUI.



# Feature Summary:

Modern UI with a light/dark theme.

The Cache Option let's you generate reports easily and fast.

Advanced Reporting through multiple parameters and multiple search values

Create spreadsheet Reports in csv and xlsx

Create nice PDF Reports for your customers.

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

:white_check_mark: Reduce the amount of API calls and faster reporting with caching optional feature

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

:white_check_mark: Pretty PDF Reports

:white_check_mark: Excel native XLSX output

:x: "Export All" Button

:x: Simple Regular expressions support in search (*,!,>,<)

:white_check_mark: Menu to create new scheduled tasks from the UI.

:x: Linux ARM & Raspberry Pi Support

## V1.5.5.x - Unforgettable Luncheon

### FEATURES

Web Interface + docker container

:x: Device statistics per OS Version, WAN IP, company, etc.)

:x: PDF/UI pie charts

:x: CPU release date for Intel Processors

:x: Customizable PDF Reports

:x: MacOS Apple Sillicon Support

## Feature wishlist & ideas

### These features might get integrated at any time or never.

:x: POST custom value fields to searched devices

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
![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/0edc46f3-2445-44f8-a75a-4525bdb1f4b1)
![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/f5084b33-bab8-46b0-b806-3e4268f61aed)


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

## Only do this if you know your way around compiling and python. Prebuilt binaries in the release section is recommended

Copy the entire git repo locally

pip install pyinstaller

pyinstaller --onefile --icon=arg.png --add-data "source;source" "Atera Report Generator.py"

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
