# Atera Report Generator Version 1.5.5
![banner3](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/49b9aba7-ccd6-447e-9f90-c202197292b3)



# Index

[News](#News)

[Feature Summary](#Feature-Summary)

[Roadmap](#Roadmap)

[CLI User Guide](#CLI-GUIDE)

# Setup

For 1.5.5.x the Default username and password is:

Username:admin

Password:ilovearg2023!

Default Access Port: 8080

Please change your admin password after the first login.

Only use ARG on your local network, a VPN or through a reverse proxy in https such as caddy or traefik.

I recommend the usage of strong passwords for the accounts. The hashing mechanism is strong but not flawless. It will get improvements soon.

# News

## 1.5.5.x (Web Edition)

The Web version is still in active developement.

It is now an entirely different beast than the the 1.5.4.x branch.

ARG Web Edition is now a self-Hosted Service supporting multiple users at the same time,

a complete admin dashboard and more! so it can be hosted on a server and support multiple tenants at the same time.

The software has been reinforced security-wise. Passwords and API Keys are now fully encrypted and secure.


## 1.5.4.x

ARG 1.5.4.4 is out!

PDF Reports are now easier on the eye and fit the overall Atera visual style.

critical bugs have been fixed

ARG now has an optional caching feature in the misc. menu,
It's awesome and is a must-have for regular power users.

Also please check out the OS End of life & geolocation features!


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

:white_check_mark: Menu to create new scheduled tasks from the UI.

## V1.5.5.x - Unforgettable Luncheon (Web Edition)

### FEATURES

:white_check_mark: Web Interface + docker container

:white_check_mark: Admin Dashboard

:x: CLI Utility to create the initial admin user and the storage_secret

:x: Web UI results

:x: "Export All" Button

:x: Simple Regular expressions support in search (*,!,>,<)

:x: Device statistics per OS Version, WAN IP, company, etc.)

:x: PDF pie charts

:x: Customizable PDF Reports

### SECURITY

:white_check_mark: Strong encryption for user passwords

:white_check_mark: Password-derived encryption for the API key

# UI Preview (1.5.5.x Branch):
![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/69cf979c-483e-4635-b1c9-c4f85598b9a5)
![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/bad6ca07-a8e6-4d92-8d23-55d7f2ddbe26)
![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/4fb55966-5ae2-4eba-8fe2-fa059210b791)
![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/892188d2-8098-4207-9aae-3c2e6643bc78)
![image](https://github.com/infovirtuel/Atera-Report-Generator/assets/134888924/b094fb7a-17f1-49e9-92b6-6dba35d43927)



# UI Preview (1.5.4.x Branch):
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
              

tqdm
