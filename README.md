# Atera Report Generator Version 1.5.3
![logo](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/d1613878-09f1-49d7-a207-8c77a85c4cdf)

# Index
[Benefits](#Benefits-to-use-the-Atera-Report-Generator)

[Feature Summary](#Feature-Summary)

[Latest Features](#Latest-Features)

[UI Previews](#UI-Previews)

[CLI User Guide](#CLI-GUIDE)

[Build from Source](#BUILD-FROM-SOURCE)

# News

ARG 1.5.3.x (Aurora Borealis) is my biggest release yet in terms of features.

I've been so excited to share it to you all and hope you find it useful.

Some features initially planned for later were implemented early.

For every 50 devices, an API query needs to be made, which slows down significantly

the whole process. local caching might help somehow but will never be perfect due to the fact some infos can change at any time.

ARG 1.5.4.x (Steamed Hams) is all about making the software more user-friendly,

faster, more secure and provide a few much needed features like regex


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

CLI Teams Reports (1.5.3.9 Release)

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

:white_check_mark: Disk Space in csv/pdf/UI/Teams output (1.5.3.8 Release)

:white_check_mark: TCP/HTTP Device Reporting

:white_check_mark: SNMP Advanced Reporting



## BACKEND

:x: remove the search options from searchops.ini (1.5.3.9 Release)

:white_check_mark: SMTP Security Enhancements (SSL and certificate verification)

:white_check_mark: unified output function to simplify adding new output methods

:white_check_mark: Remove necessity for filepath if CSV/PDF is not selected

:x: harmonisation of report rows and labels for teams/pdf/ui/csv (1.5.3.9 Release)

:white_check_mark: Cleanup of redundant functions to make the integration of http/generic/tcp devices easier

## CLI
      
:white_check_mark: simple loading animation in CLI

:white_check_mark: CLI Enhancements

:white_check_mark: Teams reports in CLI for all types (1.5.3.9 Release)

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

## Main Menu:

![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/87b92956-db52-402d-9508-882f25c42c85)

## Modules:

![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/0184d3b5-3b92-47c7-91f6-02af7f1190c6)
![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/59a35583-1be8-4838-adc9-f7a9adf7f2bf)
![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/ff5359b7-c1f8-43f0-8ad4-abe4472476f3)


## Configuration Menu:

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
                                    --onlineonly
      
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



