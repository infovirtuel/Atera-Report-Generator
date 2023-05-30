# Atera Report Generator
![logo](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/d1613878-09f1-49d7-a207-8c77a85c4cdf)
*****************
ATERA REPORT GENERATOR V1.1
*****************
NEW FEATURES:

Advanced Reporting through multiple parameters

Core Count/Processor Search
*****************
Features:

Create CSV Reports

Microsoft Teams Outputs

UI Reports
*****************
WORK-IN-PROGRESS FEATURES:

Email Output

Scheduled tasks (CLI input)

TCP/GENERIC/HTTP Device Reporting

PDF Output

XLSX Output

SNMP reporting in a secondary menu of the Agent Executable
*****************

Available Search/Reporting Options:

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

Online Only Devices

*****************
INSTRUCTIONS:

1-ENTER YOUR ATERA API KEY IN THE FIELD AND CLICK ON SAVE API KEY (REQUIRED).
THE API KEY CAN BE FOUND IN THE ADMIN PAGE OF THE CONSOLE IN THE API SECTION
HOW-TO: https://support.atera.com/hc/en-us/articles/219083397-APIs

2- ENTER YOUR TEAMS WEBHOOK URL (OPTIONAL)
IF YOU WANT TO RECEIVE THE RESULTS IN A TEAMS CHANNEL TO SHARE IT INSTANTLY WITH YOUR TEAM,
CREATE AN INCOMING WEBHOOK IN YOUR TEAMS CHANNEL AND PASTE THE GENERATED URL IN THE "TEAMS WEBHOOK URL" FIELD AND SAVE IT.

3- ENTER YOUR CSV PATH (REQUIRED)
IF PATH IS EMPTY, IT WILL THROW AN ERROR EVEN IF YOU UNCHECK SEND OUTPUT TO CSV. IF YOU DONT WANT THIS OPTION, SIMPLY
WRITE ANYTHING AND SAVE CONFIGURATION


4- SELECT A SEARCH OPTION (REQUIRED)

5- ENTER THE SEARCH VALUE (WHAT YOU ARE LOOKING FOR) IN THE SEARCH VALUE FIELD.

6- SEND OUTPUT TO TEAMS CHECKBOX (OPTIONAL)
IF YOU NEED TO SEND THE REPORT TO TEAMS, CHECK THE CHECKBOX. BY DEFAULT IT WILL DISABLED (MIGHT BE SAVED TO CONFIG FILE IN A LATER VERSION).

7- SEND OUTPUT TO CSV (OPTIONAL)
THIS IS ENABLED BY DEFAULT. ENTER THE FULL PATH TO THE FOLDER YOU WANT TO DROP THE CSV FILES INTO

8- CLICK ON SEARCH
