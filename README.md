# Atera Report Generator Version 1.5.4
![logo](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/d1613878-09f1-49d7-a207-8c77a85c4cdf)

# Index
[Benefits](#Benefits-to-use-the-Atera-Report-Generator)

[Feature Summary](#Feature-Summary)

[Latest Features](#Latest-Features)

[UI Previews](#UI-Previews)

[CLI User Guide](#CLI-GUIDE)

[Build from Source](#BUILD-FROM-SOURCE)

# News

ARG 1.4.0 is out!
Tons of things have been fixed and changed in the backend to make the experience more user friendly, the reports cleaner, and much more.

Due to the new features added, the build might feel more unstable. They can be now activated in the configuration menu.

IP Geolocalisation is here! The feature is entirely optional. It can query the public geolocalisation API of your choice.

I chose a default provider that doesn't limit queries and is fast enough so that report generation doesn't take an eternity.

The reports are now easier to read thanks to data formatting and harmonizxation of the order of rows between pdf/ui/csv/teams.

Teams Reports can also now be done through the CLI.

Configuration sanitation has been done, to make the experience a bit easier for users.

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

HTTP Device Advanced search

TCP Device Advanced Search

Disk Space in csv/pdf/UI/Teams output

CLI Teams Reports (1.5.4.0 Release)

Device Geolocation & ISP (1.5.4.0 Release)

OnlineOnly/EOL/Geolocation options can be saved in configuration menu (1.5.4.0 Release)

OS EOL information in CSV/PDF/Teams/UI (1.5.4.0 Release)

RAM and disk space shows up in gigabytes (1.5.4.0 Release)



# Feature Summary:

Advanced Reporting through multiple parameters and multiple search values

Create CSV Reports

Microsoft Teams Outputs

UI Reports

SNMP/HTTP/TCP/Agents Device Report

PDF Reports

Email Reports by Encrypted SMTP (csv, pdf attachments)

Configuration menu for Email, SMTP and API key/Webhook/local path

Encrypted sensitive informations in system keyring

Operating System End of life date/status in CSV Report.

Scheduled reports through the task scheduler or cronjobs



# Roadmap for 1.5.4.x - Steamed Hams

## BACKEND

:x: Reduce the amount of API calls and faster reporting with caching optional feature

:x: function to choose cache deprecation time 

:white_check_mark: Fix to LAN IP search in Agents Reports

:white_check_mark: Move EOL function to extract_device_information

:white_check_mark: harmonisation of report rows and labels for teams/pdf/ui/csv

## SECURITY

:x: Password-derived encryption for the API key

## UI

:white_check_mark: Dynamically resize the UI for small resolution screens

:white_check_mark: Individual tabs for General/Email/SMTP configuration menu

:white_check_mark: Each report type (device,snmp,http...) in a tab of the main menu

:white_check_mark: Cleaner and more modern UI on Windows.

## FEATURES

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

# Roadmap for V1.5.5.x - Skinners

## FEATURES

:x: Device statistics per OS Version, WAN IP, company, etc.)

:x: PDF/UI pie charts

:x: POST custom value fields to searched devices

:x: Pretty & customizable PDF Reports


# Feature wishlist & ideas

## These features might get integrated at any time or never.

Spinoffs of ARG for other popular RMMs

Import/export TCP/HTTP devices from and to Freshping

Atera API python (pip) module

Customer Contract/information reporting

Option to send email to primary contact per customer

Better loading animation for UI

Web UI (Mobile Friendly) 

SNMP/HTTP/TCP/Generic device creation menu

Warranty reports for Dell, Lenovo and HP

and more..

# UI Preview:

![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/388d21cf-2f70-499f-bfc5-6d6b1da3c0dd)



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

ttkthemes
