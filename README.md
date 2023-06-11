# Atera Report Generator Version 1.5.3.6.1
![logo](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/d1613878-09f1-49d7-a207-8c77a85c4cdf)

# Index
[Benefits](#Benefits-to-use-the-Atera-Report-Generator)

[Feature Summary](#Feature-Summary)

[Latest Features](#Latest-Features)

[UI Previews](#UI-Previews)

[Report Options](#Report-Options)

[CLI User Guide](#CLI-GUIDE)

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

Advanced CLI Interface (Scheduled Agents and SNMP reports through the Task Scheduler on windows)

Operating System End of life included in CSV Report (Optional)

Multiple search values per parameters separated by a comma (,) ex. OS Version: 2012,2019

MacOS and Linux support


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

:white_check_mark: Linux Support

:white_check_mark: MacOS Support

:x: free disk space in csv/pdf/UI output

## BACKEND

:x: move config.ini to ''%appdata%/Local/Atera Report Generator'' on windows build

:x: remove the search options from searchops.ini

:white_check_mark: SMTP Security Enhancements (SSL and certificate verification)

:white_check_mark: unified output function to simplify adding new output methods

:x: EOL report in a separate function instead of being built in csv_results

## CLI
      
:white_check_mark: simple loading animation in CLI

:white_check_mark: CLI Enhancements

## UI

:x: Combine all the output popups into a single one before UI display



# Roadmap for 1.5.4.x - Steamed Hams

## BACKEND

:x: Reduce the amount of API calls and faster reporting with caching optional feature

:x: function to choose cache deprecation time 

:white_check_mark: Cleanup of redundant functions to make the integration of http/generic/tcp devices easier

## SECURITY

:x: Password-derived encryption for API key in config.ini

## UI

:x: Individual tabs for General/Email/SMTP configuration menu

:x: Each report type (device,snmp,http...) in a tab of the main menu

## FEATURES

:x: CPU release date for Intel Processors

:x: SNMP Advanced Reporting

:x: Regular expressions support in search

:x: Menu to create new scheduled tasks from the UI.

:x: TCP/GENERIC/HTTP Device Reporting

# Roadmap for V1.5.5.x - Skinners

## FEATURES

:x: Device statistics per OS Version, WAN IP, company, etc.)

:x: PDF/UI pie charts

:x: POST custom value fields to searched devices

:x: Pretty & customizable PDF Reports

## UI

:x: Cleaner and more modern UI on Windows.

## BACKEND


# Feature wishlist & ideas

## These features might get integrated at any time or never.

Spinoff of ARG for other popular RMMs

Import/export TCP/HTTP devices from and to Freshping

Atera API python (pip) module

Customer Contract/information reporting

Option to send email to primary contact per customer

Better loading animation for UI

Web UI (Mobile Friendly) 

SNMP/HTTP/TCP/Generic device creation menu

Warranty reports for Dell, Lenovo and HP

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

# CLI GUIDE

Headless Linux doesn't work due to keyring requirement

devicename, customername, etc. on the agents report can be combined to do refined reports

SNMP report supports ONLY ONE option

EXAMPLES: 

'.\Atera Report Generator.exe' --cli --snmp --devicename forti --csv

'.\Atera Report Generator.exe' --cli --agents --ostype server --customername example --csv --pdf --email


REFERENCE SHEET:

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
                                    --onlineonly
                                    --eol


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
                                    --onlineonly
      
---------------------------------------------------------------         
--cli   
     --configure
                  #GENERAL-OPTIONS
                  --apikey VALUE   
                  --teamswebhook VALUE 
                   #SMTP-OPTIONS
                  --password VALUE 
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



