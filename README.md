# Atera Report Generator Version 1.5.3
![logo](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/d1613878-09f1-49d7-a207-8c77a85c4cdf)

# Index
[Benefits](#Benefits-to-use-the-Atera-Report-Generator)

[Feature Summary](#Feature-Summary)

[Latest Features](#Latest-Features)

[Work in progreess 1.5.3.x](#Work-in-Progress-for-1.5.3.x)

[UI Previews](#UI-Previews)

[CLI User Guide](#CLI-GUIDE)

[Build from Source](#BUILD-FROM-SOURCE)

# News



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

HTTP Device Advanced search (1.5.3.8 Release)

TCP Device Advanced Search (1.5.3.8 Release)

Disk Space in csv/pdf/UI/Teams output (1.5.3.8 Release)

CLI Teams Reports (1.5.3.8 Release)

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

# Work in Progress for 1.5.3.x - Aurora Borealis

## FEATURES
:white_check_mark: Operating System End of Life report option

:white_check_mark: Comma Separated Search

:white_check_mark: CLI Interface

:white_check_mark: Linux 64-bit Support

:white_check_mark: MacOS Intel Support

:x: Disk Space in csv/pdf/UI/Teams output (1.5.3.8 Release)

:white_check_mark: TCP/HTTP Device Reporting

:white_check_mark: SNMP Advanced Reporting



## BACKEND

:x: remove the search options from searchops.ini

:white_check_mark: SMTP Security Enhancements (SSL and certificate verification)

:white_check_mark: unified output function to simplify adding new output methods

:white_check_mark: Remove necessity for filepath if CSV/PDF is not selected

:x: harmonisation of report rows and labels for teams/pdf/ui/csv

:white_check_mark: Cleanup of redundant functions to make the integration of http/generic/tcp devices easier

## CLI
      
:white_check_mark: simple loading animation in CLI

:white_check_mark: CLI Enhancements

:x: Teams reports in CLI for all types (1.5.3.8 Release)

# Roadmap for 1.5.4.x - Steamed Hams

## BACKEND

:x: Reduce the amount of API calls and faster reporting with caching optional feature

:x: function to choose cache deprecation time 

:x: EOL report in a separate function instead of being built in csv_results

## SECURITY

:x: Password-derived encryption for the API key

## UI

:x: Dynamically resize the UI for small resolution screens

:x: Individual tabs for General/Email/SMTP configuration menu

:x: Each report type (device,snmp,http...) in a tab of the main menu

## FEATURES

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

## UI

:x: Cleaner and more modern UI on Windows.


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

# UI Previews:

Main Menu:

![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/7c666b6c-4ed0-464f-b61b-3b42650671af)


SNMP Reports:

![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/3db98a0c-1b93-4a9a-b0b8-c2c668014016)


Configuration Menu:

![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/f975b265-4209-4a2d-abe8-4535e50efb02)


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

## This section requires an update

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



