# Atera Report Generator Version 1.5.3.3
![logo](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/d1613878-09f1-49d7-a207-8c77a85c4cdf)

# Index
[Benefits](#Benefits-to-use-the-Atera-Report-Generator)

[Feature Summary](#Feature-Summary)

[Latest Features](#Latest-Features)

[UI Previews](#UI-Previews)

[Report Options](#Report-Options)

[CLI User Guide](#CLI)

# Benefits to use the Atera Report Generator

Simple interface that can be used by both begginers and advanced users

Scheduled reports by email or sent to network share or local path

Secure integration of Atera with a local environnement

Advanced reports for every customer tiers in less than 15sec*. 

Send email reports to your clients about the health of their devices

Monitor which device requires to be replaced depending on CPU Age and OS version (work in progress)

Desktop Search Engine for Atera

Open-Source and free to use for Atera Customers

* 8-10 second search estimated for 16 pages of 50 pages

#  Latest Features

Encrypted SMTP

CLI Interface

Scheduled reports through the Task Scheduler on windows

# Feature Summary:

Advanced Reporting through multiple parameters

Create CSV Reports

Microsoft Teams Outputs

UI Reports

Configuration Menu

SNMP Device Report

PDF Reports for regular devices and SNMP Devices

Email Reports by Encrypted SMTP (csv, pdf attachments) for regular devices and SNMP Devices

Configuration menu for Email and SMTP

Encrypted sensitive informations

# Work in Progress for 1.5.4 (next major build)

remove the search options from searchops.ini

Cleanup of redundant functions to make the integration of http/generic/tcp devices easier

Combine all the output popups into a single one before UI display

Remove useless code


# Work in Progress for V1.6 (next major version)


Individual tabs for General/Email/SMTP configuration menu

Device statistics per OS Version, WAN IP, company, etc.)

TCP/GENERIC/HTTP Device Reporting

SNMP Advanced Reporting

Each report type (device,snmp,http...) in a tab of the main menu


Pie Charts

# Feature wishlist for V1.7 and beyond

Option to send email to primary contact per customer

Add the loading animation to the bottom of the main window

Web UI (Mobile Friendly) 

CSV/PDF output to teams

SNMP/HTTP/TCP/Generic device creation menu

Warranty reports for Dell, Lenovo and HP

CPU and OS Version age reports


and more..

# UI Previews:

Main Menu:

![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/38c2a76c-7625-4bd7-a531-70319bb3a0ad)


SNMP Reports:

![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/42f4b61f-4e59-4aca-a99a-52ad6c5594d1)


Configuration Menu:

![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/ffecee06-65e4-4f5d-b4fc-562efb9f5cfa)



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







