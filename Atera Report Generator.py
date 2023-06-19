import requests
import json
import csv
import tkinter as tk
import configparser
import datetime
from tkinter import messagebox
from tkinter import ttk, filedialog
from PIL import ImageTk, Image
import os
from tkinter import font
import itertools
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import keyring
import sys
import ssl
import ast
import argparse
from tqdm import tqdm
import pandas as pd
import subprocess
import shutil

parser = argparse.ArgumentParser(description='')
cli_group = parser.add_argument_group('Software Options')
report_agent_group = parser.add_argument_group('Agent Report Search Options')
report_universal_group = parser.add_argument_group('Universal Search Options')
report_snmp_group = parser.add_argument_group('SNMP Report Search Options')
smtp_group = parser.add_argument_group('SMTP Configuration')
email_group = parser.add_argument_group('Email Configuration')
general_group = parser.add_argument_group('General Configuration')
output_agent_group = parser.add_argument_group('Report Options')
cli_group.add_argument('--cli', action='store_true', help='Calls the CLI Interface of Atera Report Generator')

mutually_exclusive_group = parser.add_mutually_exclusive_group()
mutually_exclusive_group.add_argument('--agents', action='store_true', help='Agents Device Search Options')
mutually_exclusive_group.add_argument('--snmp', action='store_true', help='SNMP Device Search Options')
mutually_exclusive_group.add_argument('--http', action='store_true', help='HTTP Device Options')
mutually_exclusive_group.add_argument('--tcp', action='store_true', help='TCP Device Options')
mutually_exclusive_group.add_argument('--configure', action='store_true', help='Configuration Options')


if '--agents' in sys.argv or '--snmp' in sys.argv or '--http' in sys.argv or '--tcp' in sys.argv:
    output_agent_group.add_argument('--pdf', action='store_true', help='PDF Output')
    output_agent_group.add_argument('--csv', action='store_true', help='CSV Output')
    output_agent_group.add_argument('--email', action='store_true', help='Email Output')
    output_agent_group.add_argument('--teams', action='store_true', help='MS Teams Output')
    report_universal_group.add_argument('--customername', help='Search by Customer Name')
    report_universal_group.add_argument('--devicename', help='Search by device Name')

if '--agents' in sys.argv:
    report_agent_group.add_argument('--lanip', help='Search by LAN IP')
    report_agent_group.add_argument('--ostype', help='Search by OS Type')
    report_agent_group.add_argument('--serialnumber', help='Search by Serial Number')
    report_agent_group.add_argument('--vendor', help='Search by Vendor')
    report_agent_group.add_argument('--wanip', help='Search by WAN IP')
    report_agent_group.add_argument('--domain', help='Search by Domain Name')
    report_agent_group.add_argument('--username', help='Search by Username')
    report_agent_group.add_argument('--model', help='Search by Vendor Model')
    report_agent_group.add_argument('--processor', help='Search by Processor')
    report_agent_group.add_argument('--cores', help='Search by Amount of cores')
    report_agent_group.add_argument('--os', help='Search by Operating System')

if '--snmp' in sys.argv:
    report_snmp_group.add_argument('--deviceid', help='Search by device ID')
    report_snmp_group.add_argument('--hostname', help='Search by Hostname/IP')
    report_snmp_group.add_argument('--type', help='Search by SNMP Device type')

if '--http' in sys.argv:
    report_snmp_group.add_argument('--deviceid', help='Search by device ID')
    report_snmp_group.add_argument('--url', help='Search by monitored URL')
    report_snmp_group.add_argument('--pattern', help='Search by Pattern on Website')
if '--tcp' in sys.argv:
    report_snmp_group.add_argument('--portnumber', help='Search by TCP Port')
    report_snmp_group.add_argument('--hostname', help='Search by IP or DNS Name')
    report_snmp_group.add_argument('--deviceid', help='Search by Device ID')

if '--configure' in sys.argv:
    general_group.add_argument('--apikey', help='Set the API Key in the system keyring')
    general_group.add_argument('--teamswebhook', help='Set the Teams Webhook in the system keyring')
    general_group.add_argument('--eol', help='Set the EOL option enabled or disabled in config.ini')
    general_group.add_argument('--geolocation', help='Set the geolocation option True or False in config.ini')
    general_group.add_argument('--geoprovider', help='Set the geolocation provider API URL in config.ini')
    general_group.add_argument('--onlineonly', help='Set the online Only option True or False in config.ini')
    general_group.add_argument('--filepath', help='Set the filepath for CSV/PDF Reports in config.ini')
    general_group.add_argument('--cache', help='Set the cache option True or false in config.ini')
    smtp_group.add_argument('--password', help='Set the SMTP Password in the system keyring')
    smtp_group.add_argument('--port', help='Set the SMTP Port in config.ini')
    smtp_group.add_argument('--server', help='Set the SMTP Server in config.ini')
    smtp_group.add_argument('--starttls', help='Set the StartTLS Encryption True or False for SMTP Server in config.ini')
    smtp_group.add_argument('--ssl', help='Set the StartTLS Encryption  True or False for SMTP Server in config.ini')
    smtp_group.add_argument('--username', help='Set the SMTP Username in config.ini')
    email_group.add_argument('--sender', help='Set the sender email in config.ini')
    email_group.add_argument('--recipient', help='Set the recipient email in config.ini')
    email_group.add_argument('--subject', help='Set the subject for email in config.ini')
    email_group.add_argument('--body', help='Set the body for email in config.ini')

arguments = parser.parse_args()
if arguments.cli:

    if not arguments.agents and not arguments.snmp and not arguments.configure \
            and not arguments.http and not arguments.tcp:
        sys.exit("Error: No Report Type Selected\n You can use (-h) in the CLI to see all available options")

base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
icon_img = os.path.join(base_path, 'source', 'images', 'arg2.ico')
generate_img = os.path.join(base_path, 'source', 'images', 'generate2.png')
github_img = os.path.join(base_path, 'source', 'images', 'github.png')
logo_img = os.path.join(base_path, 'source', 'images', 'banner3.png')
azure_theme = os.path.join(base_path, 'source', 'azure.tcl')


def load_decrypted_data(section, key):
    if keyring.get_keyring() is None:
        return None  # Handle case when keyring is not available

    encrypted_data = keyring.get_password("arg", key)

    if encrypted_data is None:
        return None  # Handle case when data is not found

    return encrypted_data


config_file = 'config.ini'
searchops_file = 'searchops.ini'

# Check if config.ini file exists
if not os.path.exists(config_file):
    # Create a new config.ini file
    with open(config_file, 'w') as file:
        file.write('')  # You can add initial contents if needed
# Check if searchops.ini file exists
if not os.path.exists(searchops_file):
    # Create a new searchops.ini file
    with open(searchops_file, 'w') as file:
        file.write('')  # You can add initial contents if needed
# Check if snmp_searchops.ini file exists

config = configparser.ConfigParser()
searchops = configparser.ConfigParser()
snmp_searchops = configparser.ConfigParser()
config.read('config.ini')
searchops.read('searchops.ini')
output_mode = None
chosen_eol_date = None
# Atera API
base_url = "https://app.atera.com/api/v3/"
devices_endpoint = "agents"
snmp_devices_endpoint = "devices/snmpdevices"
http_devices_endpoint = "devices/httpdevices"
tcp_devices_endpoint = "devices/tcpdevices"

# endoflife.date API
endoflife_url = "https://endoflife.date/api/"
endoflife_windows_endpoint = "windows.json"
endoflife_windows_server_endpoint = "windowsserver.json"
endoflife_macos_endpoint = "macos.json"
endoflife_ubuntu_endpoint = "ubuntu.json"
endoflife_intel_endpoint = "intel-processors.json"


def make_endoflife_request(endpoint, method="GET", params=None):
    url = endoflife_url + endpoint
    headers = {
        "Accept": "application/json",
    }

    response = requests.request(method, url, headers=headers, params=params)
    response.raise_for_status()
    return response.json()


def make_atera_request(endpoint, method="GET", params=None):
    if load_decrypted_data('arg', 'api_key'):
        apikey = load_decrypted_data('arg', 'api_key')
    if not load_decrypted_data('arg', 'api_key'):
        apikey = config['GENERAL']['api_key']

    url = base_url + endpoint
    headers = {
        "Accept": "application/json",
        "X-Api-Key": apikey
    }

    response = requests.request(method, url, headers=headers, params=params)
    response.raise_for_status()
    return response.json()


def generate_search_options():
    searchops['SearchOptions'] = {}
    searchops['SearchOptions']['device name'] = "Device Name"
    searchops['SearchOptions']['company'] = "Company"
    searchops['SearchOptions']['serial number'] = "Serial Number"
    searchops['SearchOptions']['lan ip'] = "LAN IP"
    searchops['SearchOptions']['os type'] = "OS Type"
    searchops['SearchOptions']['vendor'] = "Vendor"
    searchops['SearchOptions']['domain name'] = "Domain Name"
    searchops['SearchOptions']['username'] = "Username"
    searchops['SearchOptions']['vendor model'] = "Vendor Model"
    searchops['SearchOptions']['processor'] = "Processor"
    searchops['SearchOptions']['core amount'] = "Core Amount"
    searchops['SearchOptions']['os version'] = "OS VERSION"
    searchops['SNMPSearchOptions'] = {}
    searchops['SNMPSearchOptions']['Device Name'] = "Device Name"
    searchops['SNMPSearchOptions']['company'] = "Company"
    searchops['SNMPSearchOptions']['device id'] = "Device ID"
    searchops['SNMPSearchOptions']['hostname'] = "Hostname"
    searchops['SNMPSearchOptions']['type'] = "Type"
    searchops['HTTPSearchOptions'] = {}
    searchops['HTTPSearchOptions']['device name'] = "Device Name"
    searchops['HTTPSearchOptions']['company'] = "Company"
    searchops['HTTPSearchOptions']['device id'] = "Device ID"
    searchops['HTTPSearchOptions']['url'] = "URL"
    searchops['HTTPSearchOptions']['pattern'] = "Pattern"
    searchops['TCPSearchOptions'] = {}
    searchops['TCPSearchOptions']['device name'] = "Device Name"
    searchops['TCPSearchOptions']['company'] = "Company"
    searchops['TCPSearchOptions']['device id'] = "Device ID"
    searchops['TCPSearchOptions']['Port'] = "Port"

    with open('searchops.ini', 'w') as configfile:
        searchops.write(configfile)


generate_search_options()


def create_config():
    if 'GENERAL' not in config:
        # Create 'API' section in the config file
        config['GENERAL'] = {}
    if 'SMTP' not in config:
        # Create 'API' section in the config file
        config['SMTP'] = {}
    if 'EMAIL' not in config:
        # Create 'API' section in the config file
        config['EMAIL'] = {}
    if 'api_key' not in config['GENERAL']:
        config['GENERAL']['api_key'] = "ENCRYPTED"
    if 'teams_webhook' not in config['GENERAL']:
        config['GENERAL']['teams_webhook'] = "ENCRYPTED"
    if 'smtp_password' not in config['SMTP']:
        config['SMTP']['smtp_password'] = "ENCRYPTED"
    if 'sender_email' not in config['EMAIL']:
        config['EMAIL']['sender_email'] = "defaultsender@default.com"
    if 'recipient_email' not in config['EMAIL']:
        config['EMAIL']['recipient_email'] = "defaultrecipient@default.com"
    if 'subject' not in config['EMAIL']:
        config['EMAIL']['subject'] = "Atera Report Results"
    if 'body' not in config['EMAIL']:
        config['EMAIL']['body'] = "Please find the attached results file"
    if 'smtp_server' not in config['SMTP']:
        config['SMTP']['smtp_server'] = "smtp.office365.com"
    if 'smtp_port' not in config['SMTP']:
        config['SMTP']['smtp_port'] = "587"
    if 'smtp_username' not in config['SMTP']:
        config['SMTP']['smtp_username'] = "defaultsender@default.com"
    if 'starttls' not in config['SMTP']:
        config['SMTP']['starttls'] = "True"
    if 'ssl' not in config['SMTP']:
        config['SMTP']['ssl'] = "False"
    if 'eol' not in config['GENERAL']:
        config['GENERAL']['eol'] = "False"
    if 'geolocation' not in config['GENERAL']:
        config['GENERAL']['geolocation'] = "False"
    if 'geolocation_provider' not in config['GENERAL']:
        config['GENERAL']['geolocation_provider'] = "https://api.techniknews.net/ipgeo/"
    if 'onlineonly' not in config['GENERAL']:
        config['GENERAL']['onlineonly'] = "False"
    if 'darktheme' not in config['GENERAL']:
        config['GENERAL']['darktheme'] = "False"
    if 'lighttheme' not in config['GENERAL']:
        config['GENERAL']['lighttheme'] = "True"
    if 'cachemode' not in config['GENERAL']:
        config['GENERAL']['cachemode'] = "False"

    # Get the user's home directory
    home_dir = os.path.expanduser("~")
    desktop_path = os.path.join(home_dir, "Desktop")
    if 'filepath' not in config['GENERAL']:
        config['GENERAL']['filepath'] = f"{desktop_path}"

        # Config File Sanitation
    onlineonly_sanitation = config['GENERAL']['onlineonly']
    geolocation_sanitation = config['GENERAL']['geolocation']
    eol_sanitation = config['GENERAL']['eol']
    path_sanitation = config['GENERAL']['filepath']
    ssl_sanitation = config['SMTP']['ssl']
    starttls_sanitation = config['SMTP']['starttls']
    port_sanitation = config['SMTP']['smtp_port']
    sender_sanitation = config['EMAIL']['sender_email']
    recipient_sanitation = config['EMAIL']['recipient_email']
    geoprovider_sanitation = config['GENERAL']['geolocation_provider']
    if onlineonly_sanitation != "True" and onlineonly_sanitation != "False":
        config['GENERAL']['onlineonly'] = "False"
    if geolocation_sanitation != "True" and geolocation_sanitation != "False":
        config['GENERAL']['onlineonly'] = "False"
    if ssl_sanitation != "True" and ssl_sanitation != "False":
        config['SMTP']['ssl'] = "False"
    if starttls_sanitation != "True" and starttls_sanitation != "False":
        config['SMTP']['starttls'] = "False"
    if eol_sanitation != "True" and eol_sanitation != "False":
        config['GENERAL']['eol'] = "False"
    if not os.path.exists(path_sanitation):
        config['GENERAL']['filepath'] = f"{desktop_path}"
    if not port_sanitation.isnumeric():
        config['SMTP']['smtp_port'] = "587"
    if "@" not in sender_sanitation:
        config['EMAIL']['sender_email'] = "defaultsender@default.com"
    if "@" not in recipient_sanitation:
        config['EMAIL']['recipient_email'] = "defaultrecipient@default.com"
    if not geoprovider_sanitation.startswith("http://") and not geoprovider_sanitation.startswith("https://"):
        config['GENERAL']['geolocation_provider'] = "https://api.techniknews.net/ipgeo/"

    # ip-api.com API


create_config()


ip_api_url = config['GENERAL']['geolocation_provider']


def make_geolocation_request(device_wan_ip, method="GET", params=None):
    geolocationurl = ip_api_url + device_wan_ip
    headers = {
        "Accept": "application/json",
    }

    response = requests.request(method, geolocationurl, headers=headers, params=params)
    response.raise_for_status()
    return response.json()


with open('config.ini', 'w') as configfile:
    config.write(configfile)


create_config()


def extract_device_information(device, output_mode):
    config.read('config.ini')
    eolreport = ast.literal_eval(config['GENERAL']['eol'])
    geolocation_option = ast.literal_eval(config['GENERAL']['geolocation'])
    cachemode = config['GENERAL']['cachemode']
    if output_mode == "agents":
        device_name = device["MachineName"]
        device_company = device["CustomerName"]
        device_domain = device["DomainName"]
        device_os = device["OS"]
        device_win_version = device["OSVersion"]
        device_type = device["OSType"]
        device_ip = device["IpAddresses"]
        device_wan_ip = device["ReportedFromIP"]
        device_online = device["Online"]
        device_status = device["Online"]
        device_currentuser = device["CurrentLoggedUsers"]
        device_lastreboot = device["LastRebootTime"]
        device_serial = device["VendorSerialNumber"]
        device_windows_serial = device["WindowsSerialNumber"]
        device_processor = device["Processor"]
        device_ram = device["Memory"]
        device_vendor = device["Vendor"]
        device_model = device["VendorBrandModel"]
        device_gpu = device["Display"]
        device_os_build = device["OSBuild"]
        c_drive_free = None
        c_drive_used = None
        c_drive_total = None
        c_drive_usage_percent = None
        c_drive_total_gb = None
        c_drive_free_gb = None
        c_drive_used_gb = None
        geolocation = None
        ipisp = None
        for disk in device['HardwareDisks']:
            if disk['Drive'] == 'C:':
                c_drive_free = disk['Free']
                c_drive_used = disk['Used']
                c_drive_total = disk['Total']
                break

        if c_drive_free is not None:
            c_drive_free_gb = c_drive_free / 1024   # Convert kilobytes to gigabytes
        if c_drive_used is not None:
            c_drive_used_gb = c_drive_used / 1024
        if c_drive_total is not None:
            c_drive_total_gb = c_drive_total / 1024
        if c_drive_total_gb is not None and c_drive_used_gb is not None:
            c_drive_usage_percent = (c_drive_used_gb / c_drive_total_gb) * 100
        if device_ram is not None:
            device_ram = device_ram / 1024

        if geolocation_option:
            subdirectory = "arg_cache/geolocation_cache"
            os.makedirs(subdirectory, exist_ok=True)
            request_geo_cache = os.path.join(subdirectory, f"request_geo_{device_wan_ip}.json")
            if cachemode == "True":
                if os.path.isfile(request_geo_cache):
                    with open(request_geo_cache) as json_file:
                        geolocation_data = json.load(json_file)
                else:
                    geolocation_data = make_geolocation_request(device_wan_ip=device_wan_ip, params=None)
                    with open(request_geo_cache, "w") as json_file:
                        json.dump(geolocation_data, json_file)
            else:
                geolocation_data = make_geolocation_request(device_wan_ip=device_wan_ip, params=None)

            if geolocation_data is not None:
                ipcity = geolocation_data.get("city")
                ipregion = geolocation_data.get("regionName")
                ipcountry = geolocation_data.get("country")
                geolocation_variables = [ipcity, ipregion, ipcountry]
                geolocation = ", ".join(geolocation_variables)
                ipisp = geolocation_data.get("isp")
        if not geolocation_option:
            geolocation = ""
            ipisp = ""
        chosen_eol_date = None
        if eolreport:
            eol_subdirectory = "arg_cache/eol_cache"
            os.makedirs(eol_subdirectory, exist_ok=True)
            current_year = datetime.datetime.now().year
            current_month = datetime.datetime.now().month
            request_eol_cache = os.path.join(eol_subdirectory,
                                             f"request_eol_{current_year}_{current_month}_windowsendpoint.json")
            request_eol_cache1 = os.path.join(eol_subdirectory,
                                              f"request_eol_{current_year}_{current_month}_windowsserver.json")
            request_eol_cache2 = os.path.join(eol_subdirectory,
                                              f"request_eol_{current_year}_{current_month}_macos.json")

            if cachemode == "True":
                if os.path.isfile(request_eol_cache):
                    with open(request_eol_cache) as eol_json_file:
                        eol_response = json.load(eol_json_file)
                if os.path.isfile(request_eol_cache1):
                    with open(request_eol_cache1) as eol1_json_file:
                        eol_response1 = json.load(eol1_json_file)
                if os.path.isfile(request_eol_cache2):
                    with open(request_eol_cache2) as eol2_json_file:
                        eol_response3 = json.load(eol2_json_file)
                else:
                    eol_response = make_endoflife_request(endoflife_windows_endpoint, params=None)
                    eol_response1 = make_endoflife_request(endoflife_windows_server_endpoint, params=None)
                    eol_response3 = make_endoflife_request(endoflife_macos_endpoint, params=None)
                    with open(request_eol_cache, "w") as eol_json_file:
                        json.dump(eol_response, eol_json_file)
                    with open(request_eol_cache1, "w") as eol1_json_file:
                        json.dump(eol_response1, eol1_json_file)
                    with open(request_eol_cache2, "w") as eol2_json_file:
                        json.dump(eol_response3, eol2_json_file)

            else:
                eol_response = make_endoflife_request(endoflife_windows_endpoint, params=None)
                eol_response1 = make_endoflife_request(endoflife_windows_server_endpoint, params=None)
                eol_response3 = make_endoflife_request(endoflife_macos_endpoint, params=None)

            if 'Windows 11' in device_os or 'Windows 10' in device_os or 'Windows 7' in device_os or \
                    'Windows 8' in device_os or 'Windows 8.1' in device_os:
                if eol_response is not None and isinstance(eol_response, list):
                    for item in eol_response:
                        api_windows_version = item["cycle"]
                        api_eol_date = item["eol"]

                        if "Education" in device_os or "Enterprise" in device_os:
                            if device_win_version in api_windows_version and "(E)" in api_windows_version:
                                chosen_eol_date = api_eol_date
                                break
                        elif "Windows 1" in device_os:
                            if device_win_version in api_windows_version and "W" in api_windows_version:
                                chosen_eol_date = api_eol_date
                                break

                        elif "Windows 7" in device_os:
                            if "7 SP1" in api_windows_version:
                                chosen_eol_date = api_eol_date
                                break
                        elif "Windows 8" in device_os:
                            if "8" in api_windows_version:
                                chosen_eol_date = api_eol_date
                                break
                        elif "Windows 8.1" in device_os:
                            if "8.1" in api_windows_version:
                                chosen_eol_date = api_eol_date
                                break
                        else:
                            if device_win_version in api_windows_version and "(W)" in api_windows_version:
                                chosen_eol_date = api_eol_date
                                break

            elif 'Server' in device_os:

                if eol_response1 is not None and isinstance(eol_response1, list):
                    for item in eol_response1:
                        api_windows_srv_version = item["cycle"]
                        api_srv_eol_date = item["eol"]

                        if api_windows_srv_version in device_os:
                            chosen_eol_date = api_srv_eol_date
                            break

            elif 'macOS' in device_os:
                if eol_response3 is not None and isinstance(eol_response3, list):
                    for item in eol_response3:
                        api_codename = item["codename"]
                        api_mac_eol_date = item["eol"]
                        if api_codename in device_os:
                            if api_mac_eol_date:
                                chosen_eol_date = "deprecated"
                            else:
                                chosen_eol_date = "still supported"

                            break

        return (device_name, device_company, device_domain, device_os, device_win_version,
                device_type, device_ip, device_wan_ip, device_status, device_currentuser,
                device_lastreboot, device_serial, device_windows_serial, device_processor,
                device_ram, device_vendor, device_model, device_gpu,
                device_os_build, device_online, c_drive_free_gb,
                c_drive_used_gb, c_drive_total_gb, c_drive_usage_percent, geolocation, ipisp, chosen_eol_date)

    if output_mode == "snmp":
        device_name = device["Name"]
        device_id = device["DeviceID"]
        device_company = device["CustomerName"]
        device_hostname = device["Hostname"]
        device_online = device["Online"]
        device_type = device["Type"]
        device_security = device["SecurityLevel"]
        return (device_name, device_id, device_company,
                                 device_hostname, device_online, device_type, device_security)
    if output_mode == "http":
        device_name = device["Name"]
        device_id = device["DeviceID"]
        device_company = device["CustomerName"]
        device_url = device["URL"]
        device_online = device["URLUp"]
        device_pattern = device["Pattern"]
        device_patternup = device["ContainsPattern"]
        return device_name, device_id, device_company, device_url, device_online, device_pattern, device_patternup
    if output_mode == "tcp":
        device_name = device["Name"]
        device_id = device["DeviceID"]
        device_company = device["CustomerName"]
        tcp_port = [str(port['PortNumber']) for port in device['Ports']]
        device_online = [str(port['Available']) for port in device['Ports']]

        return device_name, device_id, device_company, device_online, tcp_port

# def temp_cache_device_information(device)


def display_results(found_devices, output_mode):

    # Create a new window
    # results_window = ThemedTk(theme="breeze")
    results_window = tk.Toplevel(window)
    results_window.iconbitmap(icon_img)
    results_window.title("Quick Report")
    # Create a text widget to display the results
    results_text = tk.Text(results_window, height=40, width=80)
    results_text.grid()
    # Insert the results into the text widget
    device_name = None
    device_id = None
    device_company = None
    device_hostname = None
    device_security = None
    device_online = None
    device_pattern = None
    device_patternup = None
    device_type = None
    device_url = None
    tcp_port = None
    device_domain = None
    device_currentuser = None
    device_os = None
    device_win_version = None
    device_windows_serial = None
    chosen_eol_date = None
    device_vendor = None
    device_model = None
    device_serial = None
    device_lastreboot = None
    device_ip = None
    device_wan_ip = None
    geolocation = None
    ipisp = None
    device_processor = None
    device_ram = None
    device_gpu = None
    c_drive_free_gb = None
    c_drive_used_gb = None
    c_drive_total_gb = None
    c_drive_usage_percent = None

    for device in found_devices:

        if output_mode == "agents":

            device_name, device_company, device_domain, device_os, device_win_version,\
                device_type, device_ip, device_wan_ip, device_status, device_currentuser,\
                device_lastreboot, device_serial, device_windows_serial, device_processor,\
                device_ram, device_vendor, device_model, device_gpu,\
                device_os_build, device_online, c_drive_free_gb, c_drive_used_gb,\
                c_drive_total_gb, c_drive_usage_percent, geolocation, \
                ipisp, chosen_eol_date = extract_device_information(device, output_mode)

        if output_mode == "snmp":
            device_name, device_id, device_company, device_hostname, device_online, \
                device_type, device_security, = extract_device_information(device, output_mode)

        if output_mode == "http":
            device_name, device_id, device_company, device_url, device_online, \
                device_pattern, device_patternup = extract_device_information(device, output_mode)
        if output_mode == "tcp":
            device_name, device_id, device_company, device_online,\
                tcp_port = extract_device_information(device, output_mode)
        if output_mode == "snmp":
            if device_name:
                results_text.insert(tk.END, f"Device Name: {device_name}\n")
            if device_id:
                results_text.insert(tk.END, f"Device ID: {device_id}\n")
            if device_company:
                results_text.insert(tk.END, f"Company: {device_company}\n")
            if device_hostname:
                results_text.insert(tk.END, f"HostName (IP): {device_hostname}\n")
            if device_type:
                results_text.insert(tk.END, f"Type: {device_type}\n")
            if device_security:
                results_text.insert(tk.END, f"Security: {device_security}\n")

        if output_mode == "http":
            if device_name:
                results_text.insert(tk.END, f"Device Name: {device_name}\n")
            if device_id:
                results_text.insert(tk.END, f"Device ID: {device_id}\n")
            if device_company:
                results_text.insert(tk.END, f"Company: {device_company}\n")
            if device_online:
                results_text.insert(tk.END, f"Online Status: {'Online' if device_online else 'Offline'}\n")
            if device_pattern:
                results_text.insert(tk.END, f"Pattern: {device_pattern}\n")
            if device_url:
                results_text.insert(tk.END, f"URL: {device_url}\n")
            if device_online:
                results_text.insert(tk.END, f"Online Status: {'Online' if device_online else 'Offline'}\n")
            if device_patternup:
                results_text.insert(tk.END,
                                    f"Pattern Status: {'Pattern is present' if device_patternup else 'No Pattern'}\n")

        if output_mode == "tcp":
            if device_name:
                results_text.insert(tk.END, f"Device Name: {device_name}\n")
            if device_id:
                results_text.insert(tk.END, f"Device ID: {device_id}\n")
            if device_company:
                results_text.insert(tk.END, f"Company: {device_company}\n")
            if tcp_port:
                results_text.insert(tk.END, f"TCP Port: {tcp_port}\n")
            if device_online:
                results_text.insert(tk.END, f"Online Status: {'Online' if device_online else 'Offline'}\n")

        if output_mode == "agents":
            if device_name:
                results_text.insert(tk.END, f"Device Name: {device_name}\n")
            if device_company:
                results_text.insert(tk.END, f"Company: {device_company}\n")
            if device_domain:
                results_text.insert(tk.END, f"Domain Name: {device_domain}\n")
            if device_currentuser:
                results_text.insert(tk.END, f"Username: {device_currentuser}\n")
            results_text.insert(tk.END, "\n")
            if device_os:
                results_text.insert(tk.END, f"OS: {device_os}\n")
            if device_win_version:
                results_text.insert(tk.END, f"OS Version: {device_win_version}\n")
            if device_windows_serial:
                results_text.insert(tk.END, f"OS Serial Number: {device_windows_serial}\n")
            if chosen_eol_date:
                results_text.insert(tk.END, f"OS End of Life: {chosen_eol_date}\n")
            results_text.insert(tk.END, "\n")
            if device_type:
                results_text.insert(tk.END, f"Device Type: {device_type}\n")
            if device_vendor:
                results_text.insert(tk.END, f"Vendor: {device_vendor}\n")
            if device_model:
                results_text.insert(tk.END, f"Machine Model: {device_model}\n")
            if device_serial:
                results_text.insert(tk.END, f"Serial Number: {device_serial}\n")
            results_text.insert(tk.END, "\n")

            if device_online:
                results_text.insert(tk.END, f"Online Status: {'Online' if device_online else 'Offline'}\n")
            if device_lastreboot:
                results_text.insert(tk.END, f"Last Reboot: {device_lastreboot}\n")
            results_text.insert(tk.END, "\n")
            if device_ip:
                results_text.insert(tk.END, f"Local IP: {device_ip}\n")
            if device_wan_ip:
                results_text.insert(tk.END, f"WAN IP: {device_wan_ip}\n")
            if geolocation:
                results_text.insert(tk.END, f"Geolocation: {geolocation}\n")
            if ipisp:
                results_text.insert(tk.END, f"ISP: {ipisp}\n")
            results_text.insert(tk.END, "\n")
            if device_processor:
                results_text.insert(tk.END, f"CPU: {device_processor}\n")
            if device_ram:
                results_text.insert(tk.END, f"RAM: {device_ram:.2f} GB\n")
            if device_gpu:
                results_text.insert(tk.END, f"GPU: {device_gpu}\n")
            if c_drive_free_gb:
                results_text.insert(tk.END, f"C: Free Disk Space: {c_drive_free_gb:.2f} GB\n")
            if c_drive_used_gb:
                results_text.insert(tk.END, f"C: Used Disk Space: {c_drive_used_gb:.2f} GB\n")
            if c_drive_total_gb:
                results_text.insert(tk.END, f"C: Total Disk Space: {c_drive_total_gb:.2f} GB\n")
            if c_drive_usage_percent:
                results_text.insert(tk.END, f"C: Disk Usage: {c_drive_usage_percent:.2f} %\n")

        results_text.insert(tk.END, f"************************\n")


def email_results(csv_output, pdf_output, csv_filename, pdf_filename, cli_mode, excel_filename):

    # Set up the email message
    msg = MIMEMultipart()
    config.read('config.ini')
    excel_output = config['GENERAL']['excel_output']
    msg['From'] = config['EMAIL']['sender_email']
    msg['To'] = config['EMAIL']['recipient_email']
    msg['Subject'] = config['EMAIL']['subject']
    body_result = config['EMAIL']['body']
    recipient_result = config['EMAIL']['recipient_email']
    sender_result = config['EMAIL']['sender_email']
    smtp_server_result = config['SMTP']['smtp_server']
    smtp_port_result = int(config['SMTP']['smtp_port'])
    smtp_username_result = config['SMTP']['smtp_username']
    smtp_password_result = None
    if load_decrypted_data('arg', 'smtp_password'):
        smtp_password_result = load_decrypted_data('arg', 'smtp_password')
    if not load_decrypted_data('arg', 'smtp_password'):
        smtp_password_result = config['SMTP']['smtp_password']
    use_starttls = ast.literal_eval(config['SMTP']['starttls'])
    use_ssl = ast.literal_eval(config['SMTP']['ssl'])
    if csv_output:
        attachment = MIMEApplication(open(csv_filename, 'rb').read())
        attachment.add_header('Content-Disposition', 'attachment', filename=csv_filename)
        msg.attach(attachment)

    if pdf_output:
        attachment = MIMEApplication(open(pdf_filename, 'rb').read())
        attachment.add_header('Content-Disposition', 'attachment', filename=pdf_filename)
        msg.attach(attachment)
    if excel_output == "True":
        attachment = MIMEApplication(open(excel_filename, 'rb').read())
        attachment.add_header('Content-Disposition', 'attachment', filename=excel_filename)
        msg.attach(attachment)

    # Add the body text to the email
    msg.attach(MIMEText(body_result, 'plain'))
    # Send the email
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_default_certs(ssl.Purpose.SERVER_AUTH)

    try:
        if use_ssl:
            with smtplib.SMTP_SSL(smtp_server_result, smtp_port_result, context=context) as server:

                server.ehlo()
                server.login(smtp_username_result, smtp_password_result)
                server.send_message(msg)
        elif use_starttls:
            with smtplib.SMTP(smtp_server_result, smtp_port_result) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(smtp_username_result, smtp_password_result)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_server_result, smtp_port_result) as server:
                server.ehlo()
                server.login(smtp_username_result, smtp_password_result)
                server.send_message(msg)
        if cli_mode:
            print("MAIL", f"Email from {sender_result} sent successfully to {recipient_result}")
        else:
            messagebox.showinfo("MAIL", f"Email from {sender_result} sent successfully to {recipient_result}")

    except smtplib.SMTPException as e:
        # Handle any SMTP exceptions
        print(f"An error occurred while sending the email: {str(e)}")


def teams_results(found_devices, search_values, output_mode, cli_mode):
    # Prepare the Adaptive Card
    adaptive_card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.3",
        "body": [
            {
                "type": "Container",
                "items": [
                    {
                        "type": "TextBlock",
                        "text": f"Report for: {search_values}",
                        "weight": "bolder",
                        "size": "large",
                        "wrap": True
                    }
                ]
            }
        ]
    }
    progress_bar_4 = tqdm(desc="Generating Teams Report...", unit=" device(s)", leave=False)

    for device in found_devices:
        if not cli_mode:
            window.update()
        if output_mode == "agents":
            device_name, device_company, device_domain, device_os, device_win_version,\
                device_type, device_ip, device_wan_ip, device_status, device_currentuser,\
                device_lastreboot, device_serial, device_windows_serial, device_processor,\
                device_ram, device_vendor, device_model, device_gpu, \
                device_os_build, device_online, c_drive_free_gb, c_drive_used_gb,\
                c_drive_total_gb, c_drive_usage_percent, geolocation, ipisp,\
                chosen_eol_date = extract_device_information(device, output_mode)

            device_container = {
                "type": "Container",
                "items": [
                    {"type": "TextBlock", "text": f"Device Name: {device_name}"},
                    {"type": "TextBlock", "text": f"Company: {device_company}"},
                    {"type": "TextBlock", "text": f"Domain: {device_domain}"},
                    {"type": "TextBlock", "text": f"Username: {device_currentuser}"},
                    {"type": "TextBlock", "text": f"OS: {device_os}"},
                    {"type": "TextBlock", "text": f"OS Version: {device_win_version}"},
                    {"type": "TextBlock", "text": f"OS Serial Number: {device_windows_serial}"},
                    {"type": "TextBlock", "text": f"OS EOL: {chosen_eol_date}"},
                    {"type": "TextBlock", "text": f"Type: {device_type}"},
                    {"type": "TextBlock", "text": f"Vendor: {device_vendor}"},
                    {"type": "TextBlock", "text": f"Model: {device_model}"},
                    {"type": "TextBlock", "text": f"Serial Number: {device_serial}"},
                    {"type": "TextBlock", "text": f"Status: {'Online' if device_online else 'Offline'}"},
                    {"type": "TextBlock", "text": f"Last Reboot: {device_lastreboot}"},
                    {"type": "TextBlock", "text": f"Local IP: {device_ip}"},
                    {"type": "TextBlock", "text": f"WAN IP: {device_wan_ip}"},
                    {"type": "TextBlock", "text": f"Geolocation: {geolocation}"},
                    {"type": "TextBlock", "text": f"ISP: {ipisp}"},
                    {"type": "TextBlock", "text": f"Processor: {device_processor}"},
                    {"type": "TextBlock", "text": f"RAM: {device_ram} GB"},
                    {"type": "TextBlock", "text": f"GPU: {device_gpu}"},
                    {"type": "TextBlock", "text": f"C: Disk Free Space: {c_drive_free_gb:.2f} GB"},
                    {"type": "TextBlock", "text": f"C: Disk Used Space: {c_drive_used_gb:.2f} GB"},
                    {"type": "TextBlock", "text": f"C: Disk Total Space: {c_drive_total_gb:.2f} GB"},
                    {"type": "TextBlock", "text": f"C: Disk Usage: {c_drive_usage_percent:.2f} %"}

                ]
            }

            # Add separator after each device except the last one
            if device != found_devices[-1]:
                device_container["separator"] = True
            adaptive_card["body"].append(device_container)

        if output_mode == "snmp":
            device_name, device_id, device_company, device_hostname, device_online, \
                device_type, device_security, = extract_device_information(device, output_mode)

            device_container = {
                "type": "Container",
                "items": [
                    {"type": "TextBlock", "text": f"Device Name: {device_name}"},
                    {"type": "TextBlock", "text": f"Device ID: {device_id}"},
                    {"type": "TextBlock", "text": f"Customer: {device_company}"},
                    {"type": "TextBlock", "text": f"Hostname: {device_hostname}"},
                    {"type": "TextBlock", "text": f"Online: {device_online}"},
                    {"type": "TextBlock", "text": f"Device Type: {device_type}"},
                    {"type": "TextBlock", "text": f"Device Security: {device_security}"},
                ]
            }
        if output_mode == "http":
            device_name, device_id, device_company, device_url, device_online,\
                device_pattern, device_patternup = extract_device_information(device, output_mode)

            device_container = {
                "type": "Container",
                "items": [
                    {"type": "TextBlock", "text": f"Device Name: {device_name}"},
                    {"type": "TextBlock", "text": f"Device ID: {device_id}"},
                    {"type": "TextBlock", "text": f"Customer: {device_company}"},
                    {"type": "TextBlock", "text": f"URL: {device_url}"},
                    {"type": "TextBlock", "text": f"Online: {device_online}"},
                    {"type": "TextBlock", "text": f"Pattern: {device_pattern}"},
                    {"type": "TextBlock", "text": f"Pattern Status: {device_patternup}"},
                ]
            }
            # Add separator after each device except the last one
            if device != found_devices[-1]:
                device_container["separator"] = True
            adaptive_card["body"].append(device_container)

        if output_mode == "tcp":
            device_name, device_id, device_company, device_online, tcp_port = extract_device_information(device,
                                                                                                         output_mode)

            device_container = {
                "type": "Container",
                "items": [
                    {"type": "TextBlock", "text": f"Device Name: {device_name}"},
                    {"type": "TextBlock", "text": f"Device ID: {device_id}"},
                    {"type": "TextBlock", "text": f"Customer: {device_company}"},
                    {"type": "TextBlock", "text": f"Online Status: {'Online' if device_online else 'Offline'}\n"},
                    {"type": "TextBlock", "text": f"Online: {device_online}"},
                    {"type": "TextBlock", "text": f"TCP Port: {tcp_port}"},
                ]
            }

            # Add separator after each device except the last one
            if device != found_devices[-1]:
                device_container["separator"] = True
            adaptive_card["body"].append(device_container)
        progress_bar_4.update(1)
    # Convert the Adaptive Card to JSON string
    adaptive_card_json = json.dumps(adaptive_card)

    # Post the Adaptive Card to Teams
    teams_webhook = load_decrypted_data('arg', 'teams_webhook')
    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": json.loads(adaptive_card_json)
            }
        ]
    }
    response = requests.post(teams_webhook, headers=headers, json=payload)
    response.raise_for_status()


def csv_results(found_devices, csv_filename, cli_mode, output_mode):
    csv_rows = []
    progress_bar_3 = tqdm(desc="Generating CSV...", unit=" device(s)", leave=False)
    device_name = None
    device_id = None
    device_company = None
    device_hostname = None
    device_security = None
    device_online = None
    device_pattern = None
    device_patternup = None
    device_type = None
    device_url = None
    tcp_port = None
    device_domain = None
    device_currentuser = None
    device_os = None
    device_win_version = None
    device_windows_serial = None
    chosen_eol_date = None
    device_vendor = None
    device_model = None
    device_serial = None
    device_lastreboot = None
    device_ip = None
    device_wan_ip = None
    geolocation = None
    ipisp = None
    device_processor = None
    device_ram = None
    device_gpu = None
    c_drive_free_gb = None
    c_drive_used_gb = None
    c_drive_total_gb = None
    c_drive_usage_percent = None
    for device in found_devices:
        if not cli_mode:
            window.update()
        if output_mode == "agents":

            device_name, device_company, device_domain, device_os, device_win_version,\
                device_type, device_ip, device_wan_ip, device_status, device_currentuser,\
                device_lastreboot, device_serial, device_windows_serial, device_processor,\
                device_ram, device_vendor, device_model, device_gpu,\
                device_os_build, device_online, c_drive_free_gb,\
                c_drive_used_gb, c_drive_total_gb, c_drive_usage_percent, \
                geolocation, ipisp, chosen_eol_date = extract_device_information(device, output_mode)

        if output_mode == "snmp":
            device_name, device_id, device_company, device_hostname,\
                device_online, device_type, device_security, = extract_device_information(device, output_mode)

        if output_mode == "http":
            device_name, device_id, device_company, device_url, device_online,\
                device_pattern, device_patternup = extract_device_information(device, output_mode)
        if output_mode == "tcp":
            device_name, device_id, device_company,\
                device_online, tcp_port = extract_device_information(device, output_mode)

        if output_mode == "agents":
            # Add device information to the CSV rows without EOL date
            csv_rows.append([device_name, device_company, device_domain,
                             device_currentuser, device_os, device_win_version, device_windows_serial, chosen_eol_date,
                             device_type, device_vendor, device_model, device_serial, device_ip, device_wan_ip,
                             geolocation, ipisp, device_processor, device_ram, device_gpu, c_drive_free_gb,
                             c_drive_used_gb, c_drive_total_gb, c_drive_usage_percent])

        if output_mode == "snmp":
            csv_rows.append([device_name, device_id, device_company,
                             device_hostname, device_online, device_type, device_security])
        if output_mode == "http":
            csv_rows.append([device_name, device_id, device_company, device_url,
                             device_online, device_pattern, device_patternup])
        if output_mode == "tcp":
            csv_rows.append([device_name, device_id, device_company, device_online, tcp_port])
        progress_bar_3.update(1)
    # Save the device information to a CSV file
    if output_mode == "agents":
        with open(csv_filename, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(["Device Name", "Company", "Domain", "Username", "OS",
                                 "OS Version", "OS Serial Number", "OS EOL", "Device Type",
                                 "Vendor", "Machine Model", "Serial Number", "Local IP", "WAN IP",
                                 "Geolocation", "ISP", "CPU",
                                 "RAM", "GPU", "C: Free Space", "C: Used Space", "C: Total Space", "C: Usage Percentage"])
            csv_writer.writerows(csv_rows)

    if output_mode == "snmp":
        with open(csv_filename, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(["Device Name", "DeviceID", "Company",
                                 "Hostname", "Online", "Type", "Security", ])
            csv_writer.writerows(csv_rows)
    if output_mode == "http":
        with open(csv_filename, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(["Device Name", "DeviceID", "Company",
                                 "URL", "Online", "Pattern", "PatternUP", ])
            csv_writer.writerows(csv_rows)
    if output_mode == "tcp":
        with open(csv_filename, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(["Device Name", "DeviceID", "Company", "Online", "Port"])
            csv_writer.writerows(csv_rows)


def pdf_results(found_devices, pdf_filename, cli_mode, output_mode):
    c = canvas.Canvas(pdf_filename, pagesize=letter)
    # Set the font and font size for the PDF
    c.setFont("Helvetica", 12)
    y = c._pagesize[1] - 50
    progress_bar_2 = tqdm(desc="Generating PDF...", unit=" device(s)", leave=False)
    # Iterate through the found devices and add the contents to the PDF
    for device in found_devices:
        device_name = None
        device_id = None
        device_company = None
        device_hostname = None
        device_security = None
        device_online = None
        device_pattern = None
        device_patternup = None
        device_type = None
        device_url = None
        tcp_port = None
        device_domain = None
        device_currentuser = None
        device_os = None
        device_win_version = None
        device_windows_serial = None
        chosen_eol_date = None
        device_vendor = None
        device_model = None
        device_serial = None
        device_lastreboot = None
        device_ip = None
        device_wan_ip = None
        geolocation = None
        ipisp = None
        device_processor = None
        device_ram = None
        device_gpu = None
        c_drive_free_gb = None
        c_drive_used_gb = None
        c_drive_total_gb = None
        c_drive_usage_percent = None
        if not cli_mode:
            window.update()
        if output_mode == "agents":

            device_name, device_company, device_domain, device_os, device_win_version,\
                device_type, device_ip, device_wan_ip, device_status, device_currentuser,\
                device_lastreboot, device_serial, device_windows_serial, device_processor,\
                device_ram, device_vendor, device_model, device_gpu,\
                device_os_build, device_online, c_drive_free_gb,\
                c_drive_used_gb, c_drive_total_gb, c_drive_usage_percent, \
                geolocation, ipisp, chosen_eol_date = extract_device_information(device, output_mode)

        if output_mode == "snmp":
            device_name, device_id, device_company, device_hostname, device_online, device_type,\
                device_security, = extract_device_information(device, output_mode)

        if output_mode == "http":
            device_name, device_id, device_company, device_url, device_online, device_pattern, \
                device_patternup = extract_device_information(device, output_mode)
        if output_mode == "tcp":
            device_name, device_id, device_company, device_online, tcp_port = extract_device_information(device, output_mode)

        # Move to the next page if the content exceeds the page height
        if y < 50:
            c.showPage()
            y = c._pagesize[1] - 50

        if device_name:
            c.drawString(50, y, f"Device Name: {device_name}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device_company:
            c.drawString(50, y, f"Company: {device_company}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50

        if output_mode == "snmp":
            if device_id:
                c.drawString(50, y, f"Device ID: {device_id}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if device_hostname:
                c.drawString(50, y, f"Hostname: {device_hostname}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if device_type:
                c.drawString(50, y, f"Device Type: {device_type}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if device_security:
                c.drawString(50, y, f"Security: {device_security}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if device_online:
                c.drawString(50, y, f"Online Status: {'Online' if device_online else 'Offline'}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50

        if output_mode == "http":
            if device_id:
                c.drawString(50, y, f"Device ID: {device_id}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if device_url:
                c.drawString(50, y, f"URL: {device_url}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if device_online:
                c.drawString(50, y, f"Online Status: {'Online' if device_online else 'Offline'}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if device_pattern:
                c.drawString(50, y, f"Pattern: {device_pattern}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if device_patternup:
                c.drawString(50, y, f"Pattern Status: {'is present' if device_patternup else 'is not present'}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50

        if output_mode == "tcp":
            if device_id:
                c.drawString(50, y, f"Device ID: {device_id}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50

            if tcp_port:
                c.drawString(50, y, f"TCP Port: {tcp_port}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if device_online:
                c.drawString(50, y, f"Online Status: {'Online' if device_online else 'Offline'}")
                y -= 20

        if output_mode == "agents":

            if device_domain:
                c.drawString(50, y, f"Domain: {device_domain}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if device_currentuser:
                c.drawString(50, y, f"Username: {device_currentuser}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50

            if device_os:
                c.drawString(50, y, f"OS: {device_os}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if device_win_version:
                c.drawString(50, y, f"OS Version: {device_win_version}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if device_windows_serial:
                c.drawString(50, y, f"OS Serial Number: {device_windows_serial}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if chosen_eol_date:
                c.drawString(50, y, f"OS EOL: {chosen_eol_date}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if device_type:
                c.drawString(50, y, f"Device Type: {device_type}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if device_vendor:
                c.drawString(50, y, f"Vendor: {device_vendor}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if device_model:
                c.drawString(50, y, f"Model: {device_model}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if device_serial:
                c.drawString(50, y, f"Serial Number: {device_serial}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if device_online:
                c.drawString(50, y, f"Online Status: {'Online' if device_online else 'Offline'}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50

            if device_lastreboot:
                c.drawString(50, y, f"Last Reboot: {device_lastreboot}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50

            if device_ip:
                c.drawString(50, y, f"Local IP: {device_ip}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if device_wan_ip:
                c.drawString(50, y, f"WAN IP: {device_wan_ip}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if geolocation:
                c.drawString(50, y, f"Geolocation: {geolocation}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if ipisp:
                c.drawString(50, y, f"ISP: {ipisp}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50

            if device_processor:
                c.drawString(50, y, f"CPU: {device_processor}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if device_ram:
                c.drawString(50, y, f"RAM: {device_ram:.2f} GB")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if device_gpu:
                c.drawString(50, y, f"GPU: {device_gpu}")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50

            if c_drive_free_gb:
                c.drawString(50, y, f"C: Free Disk Space: {c_drive_free_gb:.2f} GB")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if c_drive_used_gb:
                c.drawString(50, y, f"C: Used Disk Space: {c_drive_used_gb:.2f} GB")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if c_drive_total_gb:
                c.drawString(50, y, f"C: Free Disk Space: {c_drive_total_gb:.2f} GB")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50
            if c_drive_usage_percent:
                c.drawString(50, y, f"C: Free Disk Space: {c_drive_usage_percent:.2f} %")
                y -= 20
                if y < 50:
                    c.showPage()
                    y = c._pagesize[1] - 50

        c.drawString(50, y, "************************")
        progress_bar_2.update(1)
        y -= 30
    # Save and close the PDF file
    c.save()


def fetch_device_information(search_options, search_values, teams_output,
                             csv_output, email_output, pdf_output, cli_mode, output_mode, endpoint):
    config.read('config.ini')
    online_only = config['GENERAL']['onlineonly']
    cachemode = config['GENERAL']['cachemode']
    current_year = datetime.datetime.now().year
    current_month = datetime.datetime.now().month
    current_day = datetime.datetime.now().day
    cache_directory = f"arg_cache/atera/{output_mode}/{current_year}/{current_month}/{current_day}"
    os.makedirs(cache_directory, exist_ok=True)
    try:
        page = 1
        found_devices = []
        progress_bar = tqdm(desc="Fetching devices from Atera...", unit=" page(s)", leave=False)
        # Process all pages of devices
        while True:
            params = {"page": page, "itemsInPage": 50}
            if cachemode == "True":
                cache_filename = os.path.join(cache_directory, f"page_{page}.json")
                if os.path.isfile(cache_filename):
                    # Load devices from cache
                    with open(cache_filename) as json_file:
                        response = json.load(json_file)
                else:
                    response = make_atera_request(endpoint, params=params)
                    with open(cache_filename, "w") as json_file:
                        json.dump(response, json_file)
            else:

                response = make_atera_request(endpoint, params=params)
            devices = response["items"]

            # Process the device information
            for device in devices:
                match = True
                if not cli_mode:
                    window.update()
                # Check if the device matches the search options and values
                for option, value in zip(search_options, search_values):
                    if output_mode == "agents":
                        if option == "Device Name" and (not device['MachineName'] or not any(
                                device_name.strip().lower() in device['MachineName'].lower() for device_name in
                                value.lower().split(','))):
                            match = False
                            break
                        elif option == "Company" and (not device['CustomerName'] or not any(
                                customer_name.strip().lower() in device['CustomerName'].lower() for customer_name in
                                value.lower().split(','))):
                            match = False
                            break

                        elif option == "Serial Number" and (not device['VendorSerialNumber'] or not any(
                                serial_number.strip().lower() in device['VendorSerialNumber'].lower() for serial_number in
                                value.lower().split(','))):
                            match = False
                            break

                        elif option == "LAN IP" and (not device.get('IpAddresses') or not any(

                            any(lan_ip.strip() in ip_address for ip_address in device['IpAddresses']) for lan_ip in value.split(','))):

                            match = False

                            break

                        elif option == "OS Type" and (not device['OSType'] or not any(
                            os_type.strip().lower() in device['OSType'].lower() for os_type in
                                value.lower().split(','))):
                            match = False
                            break

                        elif option == "Vendor" and (not device['Vendor'] or not any(
                                vendor.strip().lower() in device['Vendor'].lower() for vendor in
                                value.lower().split(','))):
                            match = False
                            break

                        elif option == "Username" and (not device['LastLoginUser'] or not any(
                                username.strip().lower() in device['LastLoginUser'].lower() for username in
                                value.lower().split(','))):
                            match = False
                            break

                        elif option == "WAN IP" and (not device['ReportFromIP'] or not any(
                            wan_ip.strip().lower() in device['ReportFromIP'].lower() for wan_ip in
                                value.lower().split(','))):
                            match = False
                            break

                        elif option == "Domain Name" and (not device['DomainName'] or not any(
                            domain.strip().lower() in device['DomainName'].lower() for domain in
                                value.lower().split(','))):
                            match = False
                            break

                        elif option == "Username" and (not device['LastLoginUser'] or not any(
                            username.strip().lower() in device['LastLoginUser'].lower() for username in
                                value.lower().split(','))):
                            match = False
                            break
                        elif option == "Vendor Model" and (not device['VendorBrandModel'] or not any(
                            model.strip().lower() in device['VendorBrandModel'].lower() for model in
                                value.lower().split(','))):
                            match = False
                            break
                        elif option == "Processor" and (not device['Processor'] or not any(
                            processor.strip().lower() in device['Processor'].lower() for processor in
                                value.lower().split(','))):
                            match = False
                            break

                        elif option == "Core Amount" and int(value) != device['ProcessorCoresCount']:
                            match = False
                            break

                        elif option == "OS VERSION" and (not device['OS'] or not any(
                            os_version.strip().lower() in device['OS'].lower() for os_version in
                                value.lower().split(','))):
                            match = False
                            break

                    if output_mode == "snmp":
                        if option == "Device Name" and (not device['Name'] or not any(
                                device_name.strip().lower() in device['Name'].lower() for device_name
                                in value.lower().split(','))):
                            match = False
                            break

                        elif option == "Device ID" and int(value) != device['DeviceID']:
                            match = False
                            break
                        elif option == "Company" and (not device['CustomerName'] or not any(
                                snmp_customer_name.strip().lower() in device['CustomerName'].lower() for snmp_customer_name in
                                value.lower().split(','))):
                            match = False
                            break
                        elif option == "Hostname" and (not device['Hostname'] or not any(
                                snmp_hostname.strip().lower() in device['CustomerName'].lower() for snmp_hostname
                                in
                                value.lower().split(','))):
                            match = False
                            break
                        elif option == "Type" and (not device['Type'] or not any(
                            snmp_type.strip().lower() in device['Type'].lower() for snmp_type
                            in
                            value.lower().split(','))):
                            match = False
                            break

                    if output_mode == "http":
                        if option == "Device Name" and (not device['Name'] or not any(
                                http_device_name.strip().lower() in device['Name'].lower() for http_device_name
                                in value.lower().split(','))):
                            match = False
                            break

                        elif option == "Device ID" and int(value) != device['DeviceID']:
                            match = False
                            break
                        elif option == "Company" and (not device['CustomerName'] or not any(
                                http_customer_name.strip().lower() in device['CustomerName'].lower() for http_customer_name in
                                value.lower().split(','))):
                            match = False
                            break
                        elif option == "URL" and (not device['URL'] or not any(
                                http_url.strip().lower() in device['URL'].lower() for http_url
                                in
                                value.lower().split(','))):
                            match = False
                            break
                        elif option == "Pattern" and (not device['Pattern'] or not any(
                            http_pattern.strip().lower() in device['Pattern'].lower() for http_pattern
                            in value.lower().split(','))):
                            match = False
                            break
                    if output_mode == "tcp":
                        if option == "Device Name" and (not device['Name'] or not any(
                                tcp_device_name.strip().lower() in device['Name'].lower() for tcp_device_name
                                in value.lower().split(','))):
                            match = False
                            break

                        elif option == "Device ID" and int(value) != device['DeviceID']:
                            match = False
                            break
                        elif option == "Company" and (not device['CustomerName'] or not any(
                                tcp_customer_name.strip().lower() in device['CustomerName'].lower() for tcp_customer_name in
                                value.lower().split(','))):
                            match = False
                            break

                        elif option == "Port" and (not device['Ports'] or not any(
                            tcp_port.strip().lower() in [str(port['PortNumber']).lower() for port in device['Ports']]
                            for tcp_port in value.lower().split(','))):
                            match = False
                            break

                # Add the device to the results if it matches the search criteria
                if match:
                    if output_mode == "agents" or output_mode == "snmp":
                        if online_only == "True" and not device['Online']:
                            continue
                    if output_mode == "http":
                        if online_only and not device['URLUp']:
                            continue
                    if output_mode == "tcp":
                        if online_only and not any(port.get('Available', False) for port in device.get('Ports', [])):
                            continue

                    found_devices.append(device)

            # Break the loop if all devices have been processed
            next_page_link = response.get("nextLink")
            if next_page_link:
                page += 1
                progress_bar.update(1)
            else:
                break
        if found_devices:
            progress_bar.close()
            if cli_mode:
                print("Found Device(s). Generating Report...")

            output_results(found_devices, cli_mode,
                           teams_output, csv_output, pdf_output,
                           email_output, search_values, output_mode)

    except Exception as e:
        if cli_mode:
            print("Error", str(e))
        else:
            messagebox.showerror("Error", str(e))


# Function to handle the search button click event


def output_results(found_devices, cli_mode,
                   teams_output, csv_output, pdf_output, email_output, search_values, output_mode):
    config.read('config.ini')
    csv_filename = None
    excel_filename = None
    pdf_filename = None
    excel_output = config['GENERAL']['excel_output']
    if pdf_output:
        current_datetime = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        subfolder_name = config['GENERAL']['filepath']
        if not os.path.exists(subfolder_name):
            os.makedirs(subfolder_name)
        pdf_filename = os.path.join(subfolder_name, f"{output_mode}_pdf_report_{current_datetime}.pdf")
        pdf_results(found_devices, pdf_filename, cli_mode, output_mode)

    if csv_output:
        current_datetime = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        subfolder_name = config['GENERAL']['filepath']
        if not os.path.exists(subfolder_name):
            os.makedirs(subfolder_name)
        csv_filename = os.path.join(subfolder_name, f"{output_mode}_csv_report_{current_datetime}.csv")
        pdf_filename = os.path.join(subfolder_name, f"{output_mode}_pdf_report_{current_datetime}.pdf")
        excel_filename = os.path.join(subfolder_name, f"{output_mode}_excel_report_{current_datetime}.xlsx")
        if csv_output:
            csv_results(found_devices, csv_filename, cli_mode, output_mode)
        if excel_output:
            if excel_output == "True":
                csv_encoding = 'latin-1'
                data = pd.read_csv(csv_filename, encoding=csv_encoding)
                data.to_excel(excel_filename, index=False, )

    if teams_output:
        teams_results(found_devices, search_values, output_mode, cli_mode)

    if email_output:
        email_results(csv_output, pdf_output, csv_filename, pdf_filename, cli_mode, excel_filename)
    # Display the results in a new window
    if not cli_mode:
        display_results(found_devices, output_mode)
    if csv_output and not pdf_output:
        if cli_mode:
            print("Search Results", f"{len(found_devices)} device(s) found. "
                                    f"Device information has been saved to '{csv_filename}'.")
        else:
            messagebox.showinfo("Search Results", f"{len(found_devices)} device(s) found. "
                                                  f"Device information has been saved to '{csv_filename}'.")
    if pdf_output and not csv_output:
        if cli_mode:
            print(f"'{pdf_filename}' generated successfully!")
        else:
            messagebox.showinfo("PDF Generation", f"'{pdf_filename}' generated successfully!")
    if pdf_output and csv_output:
        if cli_mode:
            print("Search Results", f"{len(found_devices)} device(s) found. "
                                                  f"'{csv_filename}' Generated successfully! \n'{pdf_filename}' generated successfully!")
        else:
            messagebox.showinfo("Search Results", f"{len(found_devices)} device(s) found. "
                                                  f"'{csv_filename}' Generated successfully! \n\n'{pdf_filename}' generated successfully!")

    if not pdf_output and not csv_output and not cli_mode:
        messagebox.showinfo("Devices Found", f"Number of devices found: {len(found_devices)}")


def animate_loading(label):
    # Define the animation frames of a cooler animation
    animation_frames = [
        "🌑",
        "🌓",
        "🌔",
        "🌕",
        "🌖",
        "🌗",
        "🌘",
    ]

    frame_duration = 300  # Adjust the duration between frames (in milliseconds)

    def update_frame(frame_iter):
        # Get the next frame from the animation frames
        frame = next(frame_iter)
        label.config(text=frame)
        # Schedule the next update after the specified duration
        label.after(frame_duration, update_frame, frame_iter)

    frame_iter = itertools.cycle(animation_frames)
    update_frame(frame_iter)


def show_loading_window(search_options, search_values):
    # Create the loading window
    # loading_window = tk.Toplevel()
    loading_window = tk.Toplevel(window)
    # loading_window = ThemedTk(theme="breeze")
    loading_window.title("Loading Window")
    loading_window.overrideredirect(True)
    screen_width = loading_window.winfo_screenwidth()
    screen_height = loading_window.winfo_screenheight()
    window_width = 750
    window_height = 230
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    loading_window.geometry(f"{window_width}x{window_height}+{x}+{y}")
    # Add a label to display the loading message
    loading_label = ttk.Label(loading_window, font=("arial", 40))
    loading_label.grid()
    loading_label.place(relx=0.5, rely=0.2, anchor="center")
    animate_loading(loading_label)
    search_options = str(search_options).strip('[]')
    search_values = str(search_values).strip('[]')
    loading_text_label = ttk.Label(loading_window, font=("Arial", 15), text=f"Searching for..")
    loading_text_label.grid(pady=5, padx=5, sticky="nswe")
    loading_text_label.place(relx=0.5, rely=0.4, anchor="center")
    loading_text_label1 = ttk.Label(loading_window, font=("Arial", 15), text=f"Search Options:{search_options}")
    loading_text_label1.grid(pady=5, padx=5, sticky="nswe")
    loading_text_label1.place(relx=0.5, rely=0.6, anchor="center")
    loading_text_label2 = ttk.Label(loading_window, font=("Arial", 15), text=f"Search values:{search_values}")
    loading_text_label2.grid(pady=5, padx=5, sticky="nswe")
    loading_text_label2.place(relx=0.5, rely=0.8, anchor="center")

    return loading_window


def search_button_clicked(event=None):
    # Get the selected search options and value
    output_mode = None

    search_options = []
    search_values = []

    for y, var in enumerate(tcp_option_vars):
        tcp_option = var.get()
        tcp_value = tcp_value_entries[y].get()

        if tcp_option != "None" and tcp_value.strip() != "":
            output_mode = "tcp"
            search_options.append(tcp_option)
            search_values.append(tcp_value)

    for y, var in enumerate(snmp_option_vars):
        snmp_option = var.get()
        snmp_value = snmp_value_entries[y].get()

        if snmp_option != "None" and snmp_value.strip() != "":
            output_mode = "snmp"
            search_options.append(snmp_option)
            search_values.append(snmp_value)

    for i, var in enumerate(option_vars):
        option = var.get()
        value = value_entries[i].get()

        if option != "None" and value.strip() != "":
            output_mode = "agents"
            search_options.append(option)
            search_values.append(value)

    for y, var in enumerate(http_option_vars):
        http_option = var.get()
        http_value = http_value_entries[y].get()

        if http_option != "None" and http_value.strip() != "":
            output_mode = "http"
            search_options.append(http_option)
            search_values.append(http_value)

    # Check if any search options were selected

    if output_mode == "agents":
        chosen_endpoint = devices_endpoint
    elif output_mode == "snmp":
        chosen_endpoint = snmp_devices_endpoint
    elif output_mode == "tcp":
        chosen_endpoint = tcp_devices_endpoint
    elif output_mode == "http":
        chosen_endpoint = http_devices_endpoint
    else:
        messagebox.showwarning("Warning", "Please Enter a value for at least one search option.")
        return

    if not search_options:

        messagebox.showwarning("Warning", "Please Enter a value for at least one search option.")
        return
    # Fetch device information based on the selected options
    loading_window = show_loading_window(search_options, search_values)
    fetch_device_information(search_options, search_values, teams_output_var.get(), csv_output_var.get(),
                             email_output_var.get(), pdf_output_var.get(),
                             cli_mode=False, output_mode=output_mode, endpoint=chosen_endpoint)
    loading_window.destroy()


def open_task_scheduler():
    try:
        subprocess.Popen("taskschd.msc", shell=True)
    except FileNotFoundError:
        print("Task Scheduler not found on this system.")


def open_cmd_at_executable_path():
    try:
        executable_path = os.path.dirname(os.path.abspath(__file__))  # Get the path of the executable
        subprocess.Popen(['start', 'cmd', '/K', 'cd', '/D', executable_path], shell=True)
    except Exception as e:
        print("Error opening Command Prompt:", e)


def delete_cache_folder():
    cache_directory = "arg_cache"

    # Check if cache directory exists
    if os.path.exists(cache_directory):
        # Remove the cache directory and all its contents
        shutil.rmtree(cache_directory)


def save_config(event=None):

    def save_general_config():
        save_api_key = api_key_entry.get()
        save_teams_webhook = webhook_entry.get()
        save_subfolder_name = filepath_entry.get()
        save_geolocation = geolocation_option_var.get()
        save_geoprovider = geoprovider_entry.get()
        save_eol = eol_option_var.get()
        save_onlineonly = online_only_var.get()
        save_excel = excel_var.get()
        save_dark_theme = dark_theme_var.get()
        save_light_theme = light_theme_var.get()
        save_cache_mode = cache_var.get()
        # Store encrypted api key and webhook URL in keyring
        keyring.set_password("arg", "api_key", save_api_key)
        keyring.set_password("arg", "teams_webhook", save_teams_webhook)

        config['GENERAL'] = {
            'filepath': save_subfolder_name,
            'geolocation': save_geolocation,
            'geolocation_provider': save_geoprovider,
            'eol': save_eol,
            'onlineonly': save_onlineonly,
            'excel_output': save_excel,
            'darktheme': save_dark_theme,
            'lighttheme': save_light_theme,
            'cachemode': save_cache_mode,



        }
        with open('config.ini', 'w') as configfile:
            config.write(configfile)

    def save_email_config():
        email_recipient = recipient_entry.get()
        email_sender = sender_entry.get()
        email_subject = subject_entry.get()
        email_body = body_entry.get("1.0", "end-1c")
        config['EMAIL'] = {
            'sender_email': email_sender,
            'recipient_email': email_recipient,
            'subject': email_subject,
            'body': email_body

        }
        with open('config.ini', 'w') as configfile:
            config.write(configfile)

    def save_smtp_config():
        save_smtp_server = smtp_server_entry.get()
        save_smtp_port = smtp_port_entry.get()
        save_smtp_username = smtp_username_entry.get()
        save_smtp_password = smtp_password_entry.get()
        use_starttls = starttls_var.get()
        use_ssl = ssl_var.get()
        # Saves SMTP Password to System Keyring
        keyring.set_password("arg", "smtp_password", save_smtp_password)

        config['SMTP'] = {
            'smtp_server': save_smtp_server,
            'smtp_port': save_smtp_port,
            'smtp_username': save_smtp_username,
            'starttls': use_starttls,
            'ssl': use_ssl
        }
        with open('config.ini', 'w') as configfile:
            config.write(configfile)

    save_smtp_config()
    save_email_config()
    save_general_config()
    messagebox.showinfo("Configuration", "Configuration Saved!")


# CLI Interface Logic
if arguments.cli:

    if arguments.configure:

        if arguments.apikey:
            keyring.set_password("arg", "api_key", arguments.apikey)
            print("Successfully saved API Key")

        if arguments.teamswebhook:
            if arguments.teamswebhook.startswith("https://"):
                keyring.set_password("arg", "teams_webhook", arguments.teamswebhook)
                print("Successfully saved MS Teams Webhook")
            else:
                print("Teams Webhook needs to start with 'https://'")

        if arguments.password:
            keyring.set_password("arg", "smtp_password", arguments.password)
            print("Successfully saved SMTP Password")

        if arguments.filepath:
            if os.path.exists(arguments.filepath):
                config['GENERAL'] = {
                    'filepath': arguments.filepath,
                }
                with open('config.ini', 'w') as configfile:
                    config.write(configfile)
                    print("Successfully saved filepath")
            else:
                print("Path does not exist")

        if arguments.port:
            if arguments.port.isnumeric():
                if 'SMTP' in config:
                    if 'smtp_port' in config['SMTP']:
                        config['SMTP']['smtp_port'] = arguments.port
                    else:
                        config['SMTP'].update({
                            'smtp_port': arguments.port,
                        })
                else:
                    config['SMTP'] = {
                        'smtp_port': arguments.port,
                    }

                with open('config.ini', 'w') as configfile:
                    config.write(configfile)
                    print("Successfully saved SMTP Port")
            else:
                print("Port cannot contain non-numeric characters")

        if arguments.server:
            if 'SMTP' in config:
                if 'smtp_server' in config['SMTP']:
                    config['SMTP']['smtp_server'] = arguments.server
                else:
                    config['SMTP'].update({
                        'smtp_server': arguments.server,
                    })
            else:
                config['SMTP'] = {
                    'smtp_server': arguments.server,
                }

            with open('config.ini', 'w') as configfile:
                config.write(configfile)
                print("Successfully saved SMTP Server")
        if arguments.starttls:
            if arguments.geolocation == "True" or arguments.geolocation == "False":
                if 'SMTP' in config:
                    if 'starttls' in config['SMTP']:
                        config['SMTP']['starttls'] = arguments.starttls
                    else:
                        config['SMTP'].update({
                            'starttls': arguments.starttls,
                        })
                else:
                    config['SMTP'] = {
                        'starttls': arguments.starttls,
                    }

                with open('config.ini', 'w') as configfile:
                    config.write(configfile)
                    print("Successfully saved StartTLS Setting")
            else:
                print("Value must be True or False")
        if arguments.ssl:
            if arguments.geolocation == "True" or arguments.geolocation == "False":
                if 'SMTP' in config:
                    if 'ssl' in config['SMTP']:
                        config['SMTP']['ssl'] = arguments.ssl
                    else:
                        config['SMTP'].update({
                            'ssl': arguments.ssl,
                        })
                else:
                    config['SMTP'] = {
                        'ssl': arguments.ssl,
                    }

                with open('config.ini', 'w') as configfile:
                    config.write(configfile)
                    print("Successfully saved SSL Setting")
            else:
                print("Value must be True or False")

        if arguments.sender:
            if "@" in arguments.sender:
                if 'EMAIL' in config:
                    if 'sender_email' in config['EMAIL']:
                        config['EMAIL']['sender_email'] = arguments.sender
                    else:
                        config['EMAIL'].update({
                            'sender_email': arguments.sender,
                        })
                else:
                    config['EMAIL'] = {
                        'sender_email': arguments.sender,
                    }

                with open('config.ini', 'w') as configfile:
                    config.write(configfile)
                    print("Successfully saved Email Sender")
            else:
                print("invalid email address")
        if arguments.recipient:
            if "@" in arguments.recipient:
                if 'EMAIL' in config:
                    if 'recipient_email' in config['EMAIL']:
                        config['EMAIL']['recipient_email'] = arguments.recipient
                    else:
                        config['EMAIL'].update({
                            'recipient_email': arguments.recipient,
                        })
                else:
                    config['EMAIL'] = {
                        'recipient_email': arguments.recipient,
                    }

                with open('config.ini', 'w') as configfile:
                    config.write(configfile)
                    print("Successfully saved Email Recipient")
            else:
                print("invalid email address.")

        if arguments.subject:
            if 'EMAIL' in config:
                if 'subject' in config['EMAIL']:
                    config['EMAIL']['subject'] = arguments.subject
                else:
                    config['EMAIL'].update({
                        'subject': arguments.subject,
                    })
            else:
                config['EMAIL'] = {
                    'subject': arguments.subject,
                }

            with open('config.ini', 'w') as configfile:
                config.write(configfile)
                print("Successfully saved Email Subject")
        if arguments.body:
            if 'EMAIL' in config:
                if 'body' in config['EMAIL']:
                    config['EMAIL']['body'] = arguments.body
                else:
                    config['EMAIL'].update({
                        'body': arguments.body,
                    })
            else:
                config['EMAIL'] = {
                    'body': arguments.body,
                }

            with open('config.ini', 'w') as configfile:
                config.write(configfile)
                print("Successfully saved Email Body")

        if arguments.eol:
            if arguments.geolocation == "True" or arguments.geolocation == "False":
                if 'GENERAL' in config:
                    if 'eol' in config['GENERAL']:
                        config['GENERAL']['eol'] = arguments.eol
                    else:
                        config['GENERAL'].update({
                            'eol': arguments.eol,
                        })
                else:
                    config['GENERAL'] = {
                        'eol': arguments.eol,
                    }

                with open('config.ini', 'w') as configfile:
                    config.write(configfile)
                    print("Successfully saved EOL Setting")
            else:
                print("Value must be True or False")

        if arguments.cache:
            if arguments.cache == "True" or arguments.cache == "False":
                if 'GENERAL' in config:
                    if 'cachemode' in config['GENERAL']:
                        config['GENERAL']['cachemode'] = arguments.cache
                    else:
                        config['GENERAL'].update({
                            'cachemode': arguments.cache,
                        })
                else:
                    config['GENERAL'] = {
                        'cachemode': arguments.cache,
                    }

                with open('config.ini', 'w') as configfile:
                    config.write(configfile)
                    print("Successfully saved cache setting")
            if arguments.cache == "flush" or arguments.cache == "delete":
                delete_cache_folder()
                print("Successfully flushed cache")
            else:
                print("Value must be True or False")

        if arguments.geolocation:
            if arguments.geolocation == "True" or arguments.geolocation == "False":
                if 'GENERAL' in config:
                    if 'geolocation' in config['GENERAL']:
                        config['GENERAL']['geolocation'] = arguments.geolocation
                    else:
                        config['GENERAL'].update({
                            'geolocation': arguments.geolocation,
                        })
                else:
                    config['GENERAL'] = {
                        'geolocation': arguments.geolocation,
                    }

                with open('config.ini', 'w') as configfile:
                    config.write(configfile)
                    print("Successfully saved Geolocation Setting")
            else:
                print("Value must be True or False")
        if arguments.onlineonly:
            if arguments.onlineonly == "True" or arguments.onlineonly == "False":
                if 'GENERAL' in config:
                    if 'onlineonly' in config['GENERAL']:
                        config['GENERAL']['onlineonly'] = arguments.onlineonly
                    else:
                        config['GENERAL'].update({
                            'onlineonly': arguments.onlineonly,
                        })
                else:
                    config['GENERAL'] = {
                        'onlineonly': arguments.onlineonly,
                    }
                with open('config.ini', 'w') as configfile:
                    config.write(configfile)
                    print("Successfully saved Online Only Setting")
            else:
                print("Value must be True or False")

        if arguments.geoprovider:
            if arguments.geoprovider.startswith("http://") or arguments.geoprovider.startswith("https://"):
                if 'GENERAL' in config:
                    if 'geolocation_provider' in config['GENERAL']:
                        config['GENERAL']['geolocation_provider'] = arguments.geoprovider
                    else:
                        config['GENERAL'].update({
                            'geolocation_provider': arguments.geoprovider,
                        })
                else:
                    config['GENERAL'] = {
                        'geolocation_provider': arguments.geoprovider,
                    }

                with open('config.ini', 'w') as configfile:
                    config.write(configfile)
                    print("Successfully saved Online Only Setting")
            else:
                print("Value must start with 'http://' or 'https://' ")
        if arguments.username:
            if 'SMTP' in config:
                if 'smtp_username' in config['SMTP']:
                    config['SMTP']['smtp_username'] = arguments.username
                else:
                    config['SMTP'].update({
                        'smtp_username': arguments.username,
                    })
            else:
                config['SMTP'] = {
                    'smtp_username': arguments.username,
                }

            with open('config.ini', 'w') as configfile:
                config.write(configfile)
                print("Successfully saved SMTP Username")

    if arguments.agents:
        pdf_output = arguments.pdf
        csv_output = arguments.csv
        email_output = arguments.email
        teams_output = arguments.teams
        device_name = arguments.devicename
        customer_name = arguments.customername
        serial_number = arguments.serialnumber
        lan_ip = arguments.lanip
        os_type = arguments.ostype
        vendor = arguments.vendor
        wan_ip = arguments.wanip
        domain = arguments.domain
        username = arguments.username
        model = arguments.model
        processor = arguments.processor
        cores = arguments.cores
        os_version = arguments.os

        search_options = []
        search_values = []

        if device_name:
            search_options.append('Device Name')
            search_values.append(device_name)
        if customer_name:
            search_options.append('Company')
            search_values.append(customer_name)
        if serial_number:
            search_options.append('Serial Number')
            search_values.append(serial_number)
        if lan_ip:
            search_options.append('LAN IP')
            search_values.append(lan_ip)
        if os_type:
            search_options.append('OS Type')
            search_values.append(os_type)
        if vendor:
            search_options.append('Vendor')
            search_values.append(vendor)
        if wan_ip:
            search_options.append('WAN IP')
            search_values.append(wan_ip)
        if domain:
            search_options.append('Domain Name')
            search_values.append(domain)
        if username:
            search_options.append('Username')
            search_values.append(username)
        if model:
            search_options.append('Vendor Model')
            search_values.append(model)
        if processor:
            search_options.append('Processor')
            search_values.append(processor)
        if cores:
            search_options.append('Core Amount')
            search_values.append(cores)
        if os_version:
            search_options.append('OS VERSION')
            search_values.append(os_version)

        elif not any(
                [device_name, customer_name, serial_number, lan_ip, os_type,
                 vendor, wan_ip, domain, username, model, processor, cores, os_version]):

            if arguments.cli:
                sys.exit("No valid options provided\nYou can use (-h) to see available options")

        fetch_device_information(search_options, search_values, teams_output=teams_output, csv_output=csv_output,
                                 email_output=email_output, pdf_output=pdf_output,
                                 cli_mode=True, output_mode="agents",
                                 endpoint=devices_endpoint)

    if arguments.snmp:
        pdf_output = arguments.pdf
        csv_output = arguments.csv
        teams_output = arguments.teams
        email_output = arguments.email
        snmp_device_name = arguments.devicename
        snmp_device_id = arguments.deviceid
        snmp_hostname = arguments.hostname
        snmp_customer_name = arguments.customername
        snmp_type = arguments.type
        search_options = []
        search_values = []

        if snmp_device_name:
            search_options.append('Device Name')
            search_values.append(snmp_device_name)
        if snmp_device_id:
            search_options.append('Device ID')
            search_values.append(snmp_device_id)
        if snmp_customer_name:
            search_options.append('Company')
            search_values.append(snmp_customer_name)
        if snmp_hostname:
            search_options.append('Hostname')
            search_values.append(snmp_customer_name)
        if snmp_type:
            search_options.append('Type')
            search_values.append(snmp_type)
        elif not any(
                [snmp_device_name, snmp_device_id, snmp_customer_name, snmp_hostname, snmp_type]):
            if arguments.cli:
                sys.exit("No valid options provided\nYou can use (-h) to see available options")

        fetch_device_information(search_options, search_values, teams_output=teams_output, csv_output=csv_output,
                                 email_output=email_output, pdf_output=pdf_output, cli_mode=True,
                                 output_mode="snmp", endpoint=snmp_devices_endpoint)

    if arguments.http:
        pdf_output = arguments.pdf
        csv_output = arguments.csv
        teams_output = arguments.teams
        email_output = arguments.email
        http_device_name = arguments.devicename
        http_device_id = arguments.deviceid
        http_url = arguments.url
        http_pattern = arguments.pattern
        http_customer_name = arguments.customername
        search_options = []
        search_values = []

        if http_device_name:
            search_options.append('Device Name')
            search_values.append(http_device_name)
        if http_device_id:
            search_options.append('Device ID')
            search_values.append(http_device_id)
        if http_customer_name:
            search_options.append('Company')
            search_values.append(http_customer_name)
        if http_url:
            search_options.append('URL')
            search_values.append(http_url)
        if http_pattern:
            search_options.append('Pattern')
            search_values.append(http_pattern)
        elif not any(
                [http_device_name, http_device_id, http_customer_name, http_url, http_pattern]):
            if arguments.cli:
                sys.exit("No valid options provided\nYou can use (-h) to see available options")

        fetch_device_information(search_options, search_values, teams_output=teams_output, csv_output=csv_output,
                                 email_output=email_output, pdf_output=pdf_output, cli_mode=True,
                                 output_mode="http", endpoint=http_devices_endpoint)

    if arguments.tcp:
        pdf_output = arguments.pdf
        csv_output = arguments.csv
        teams_output = arguments.teams
        email_output = arguments.email
        tcp_device_name = arguments.devicename
        tcp_device_id = arguments.deviceid
        tcp_hostname = arguments.hostname
        tcp_port = arguments.portnumber
        tcp_customer_name = arguments.customername
        search_options = []
        search_values = []

        if tcp_device_name:
            search_options.append('Device Name')
            search_values.append(tcp_device_name)
        if tcp_device_id:
            search_options.append('Device ID')
            search_values.append(tcp_device_id)
        if tcp_customer_name:
            search_options.append('Company')
            search_values.append(tcp_customer_name)
        if tcp_port:
            search_options.append('Port')
            search_values.append(tcp_port)
        elif not any(
                [tcp_device_name, tcp_device_id, tcp_customer_name, tcp_port]):
            if arguments.cli:
                sys.exit("No valid options provided\nYou can use (-h) to see available options")

        fetch_device_information(search_options, search_values, teams_output=teams_output, csv_output=csv_output,
                                 email_output=email_output, pdf_output=pdf_output, cli_mode=True,
                                 output_mode="tcp", endpoint=tcp_devices_endpoint)

# Tkinter Graphical Interface
else:
    sys.stdin and sys.stdin.isatty()
    window = tk.Tk()
    # window = ThemedTk(theme="breeze")
    window.iconbitmap(icon_img)
    window.tk.call("source", azure_theme)
    config.read('config.ini')
    darktheme = config['GENERAL']['darktheme']
    lighttheme = config['GENERAL']['lighttheme']
    if lighttheme == "True":
        window.tk.call("set_theme", "light")
    if darktheme == "True":
        window.tk.call("set_theme", "dark")
    window.title("Atera Report Generator 1.5.4.2.2 - Steamed Hams")
    images_folder = "images"
    image_path = logo_img
    image = Image.open(image_path)
    image = image.resize((630, 75), Image.LANCZOS)
    # Create an ImageTk object to display the image in the GUI
    photo = ImageTk.PhotoImage(image)
    window.grid_rowconfigure(0, weight=1)
    window.grid_columnconfigure(0, weight=1)
    canvas1 = tk.Canvas(window, width=630, height=766)  # Adjust the dimensions as needed
    canvas1.grid(row=0, column=0, sticky="nsew")
    scrollbar = ttk.Scrollbar(window, style="TScrollbar", command=canvas1.yview)
    scrollbar.grid(row=0, column=1, sticky="ns")
    canvas1.configure(yscrollcommand=scrollbar.set)
    big_content_frame = tk.Frame(canvas1)
    big_content_frame.grid()
    canvas1.create_window((0, 0), window=big_content_frame, anchor="nw")

    def update_canvas_scroll_region(event):
        canvas1.configure(scrollregion=canvas1.bbox("all"))

    def on_canvas_configure(event):
        canvas1.configure(scrollregion=canvas1.bbox("all"))
    canvas1.bind("<Configure>", on_canvas_configure)
    big_content_frame.bind("<Configure>", update_canvas_scroll_region)

    def on_mousewheel(event):
        canvas1.yview_scroll(int(-1 * (event.delta / 120)), "units")

    canvas1.bind_all("<MouseWheel>", on_mousewheel)


    def change_theme():
        # NOTE: The theme's real name is azure-<mode>
        if window.tk.call("ttk::style", "theme", "use") == "azure-dark":
            # Set light theme
            window.tk.call("set_theme", "light")
        else:
            # Set dark theme
            window.tk.call("set_theme", "dark")


    # Create a label to display the image
    image_label = ttk.Label(big_content_frame, image=photo)
    image_label.grid(row=1, column=1, columnspan=2, sticky="nw")

    mainmenu = ttk.Notebook(big_content_frame)
    mainmenu.grid(row=2, column=1, padx=10, pady=2, sticky="nw")
    agents_frame = ttk.Frame(mainmenu)
    snmp_frame = ttk.Frame(mainmenu)
    tcp_frame = ttk.Frame(mainmenu)
    http_frame = ttk.Frame(mainmenu)
    mainmenu.add(agents_frame, text="Agents")
    mainmenu.add(snmp_frame, text="SNMP")
    mainmenu.add(tcp_frame, text="TCP")
    mainmenu.add(http_frame, text="HTTP")

    options_frame = ttk.LabelFrame(agents_frame, text="Search Options")
    options_frame.grid(row=2, column=1, padx=10, pady=2, sticky="n")

    options = searchops.options('SearchOptions')
    snmp_options = searchops.options('SNMPSearchOptions')
    http_options = searchops.options('HTTPSearchOptions')
    # Create search option variables and value entry widgets
    option_vars = []
    value_entries = []
    snmp_option_vars = []
    snmp_value_entries = []
    http_option_vars = []
    http_value_entries = []
    tcp_option_vars = []
    tcp_value_entries = []

    num_options = len(searchops.options('SearchOptions'))
    options_per_column = min(num_options, 10)
    options_remaining = num_options

    for i, option in enumerate(searchops.options('SearchOptions')):
        option_var = tk.StringVar()
        option_var.set(searchops['SearchOptions'][option])
        option_label = ttk.Label(agents_frame, text=option)
        option_label.grid(row=i, column=0, padx=5, pady=5, sticky="w")

        value_entry = ttk.Entry(agents_frame)
        value_entry.grid(row=i, column=1, padx=5, pady=5)
        value_entry.bind("<Return>", search_button_clicked)
        option_vars.append(option_var)
        value_entries.append(value_entry)
    # Create a frame for the Configuration

    bottom_frame = ttk.LabelFrame(big_content_frame, text="New Features")
    bottom_frame.grid(row=4, column=1, columnspan=2, sticky="s")

    # Create a frame for the Output
    output_frame = ttk.Frame(big_content_frame, style='Card.TFrame')
    output_frame.grid(row=3, column=1, sticky="n", columnspan=2, padx=10, pady=10)

    # Create a checkbox for Teams output
    teams_output_var = tk.BooleanVar(value=False)
    teams_output_checkbutton = \
        ttk.Checkbutton(output_frame, text="Microsoft Teams", style='Switch.TCheckbutton', variable=teams_output_var)
    teams_output_checkbutton.grid(padx=5, pady=5, column=4, row=1)
    # Create a checkbox for CSV output
    csv_output_var = tk.BooleanVar(value=False)
    csv_output_checkbutton = \
        ttk.Checkbutton(output_frame, text="Spreadsheet", style='Switch.TCheckbutton', variable=csv_output_var)
    csv_output_checkbutton.grid(padx=5, pady=5, column=3, row=1)
    pdf_output_var = tk.BooleanVar(value=False)
    pdf_output_checkbutton = \
        ttk.Checkbutton(output_frame, text="PDF", style='Switch.TCheckbutton', variable=pdf_output_var)
    pdf_output_checkbutton.grid(padx=5, pady=5, column=2, row=1)
    email_output_var = tk.BooleanVar(value=False)
    email_output_checkbutton = \
        ttk.Checkbutton(output_frame, text="Email", style='Switch.TCheckbutton', variable=email_output_var)
    email_output_checkbutton.grid(padx=5, pady=5, column=1, row=1)

    notebook = ttk.Notebook(big_content_frame)
    general_tab = ttk.Frame(notebook)
    email_tab = ttk.Frame(notebook)
    smtp_tab = ttk.Frame(notebook)
    ui_tab = ttk.Frame(notebook)
    cli_tab = ttk.Frame(notebook)
    notebook.add(general_tab, text="General")
    notebook.add(email_tab, text="Email")
    notebook.add(smtp_tab, text="SMTP")
    notebook.add(cli_tab, text="CLI")
    notebook.add(ui_tab, text="Misc")
    notebook.grid(row=2, column=2, sticky="n")

    # API KEY GUI ENTRY

    api_key_frame = ttk.LabelFrame(general_tab, text=" Atera API Key")
    api_key_frame.grid(padx=10, pady=0, column=2)
    api_key_entry = ttk.Entry(api_key_frame, width=30)
    api_key_entry.grid(padx=10, pady=10)
    api_key_entry.bind("<Return>", save_config)
    api_key = load_decrypted_data('arg', 'api_key')
    if api_key is not None:
        api_key_entry.insert(0, api_key)
    else:
        api_key_entry.insert(0, "Empty")  # Set a default value or empty string

    # WEBHOOK GUI ENTRY
    webhook_frame = ttk.LabelFrame(general_tab, text="Teams Webhook URL")
    webhook_frame.grid(padx=10, pady=10, column=2)
    webhook_entry = ttk.Entry(webhook_frame, width=30)
    webhook_entry.grid(padx=10, pady=10)
    webhook_entry.bind("<Return>", save_config)
    teams_webhook = load_decrypted_data('arg', 'teams_webhook')
    if teams_webhook is not None:
        webhook_entry.insert(0, teams_webhook)
    else:
        webhook_entry.insert(0, "Empty")  # Set a default value or empty string

    output_options_frame = ttk.LabelFrame(general_tab, text="Report options")
    output_options_frame.grid(padx=10, pady=5, column=2)
    eol_option_var = tk.BooleanVar(value=config['GENERAL'].getboolean('eol', False))
    eol_option_checkbox = ttk.Checkbutton(output_options_frame, text="OS End of Life", variable=eol_option_var)
    eol_option_checkbox.grid(row=1, column=1, padx=10, sticky="w")
    geolocation_option_var = tk.BooleanVar(value=config['GENERAL'].getboolean('geolocation', False))
    geolocation_option_checkbox = \
        ttk.Checkbutton(output_options_frame, text="Geolocation", variable=geolocation_option_var)
    geolocation_option_checkbox.grid(row=1, column=2, padx=10)
    online_only_var = tk.BooleanVar(value=config['GENERAL'].getboolean('onlineonly', False))
    online_only_checkbox = ttk.Checkbutton(output_options_frame, text="Online Devices", variable=online_only_var)
    online_only_checkbox.grid(row=2, column=1, padx=10)

    excel_var = tk.BooleanVar(value=config['GENERAL'].getboolean('excel_output', False))
    excel_checkbox = ttk.Checkbutton(output_options_frame, text="XLSX file", variable=excel_var)
    excel_checkbox.grid(row=2, column=2, padx=10, sticky="w")

    geoprovider_frame = ttk.LabelFrame(general_tab, text="Geolocation provider (API)")
    geoprovider_frame.grid(padx=10, pady=10, column=2)
    geoprovider_entry = ttk.Entry(geoprovider_frame, width=30)
    geoprovider_entry.grid(padx=10, pady=10)
    geoprovider_entry.bind("<Return>", save_config)
    geoprovider = config['GENERAL']['geolocation_provider']
    if geoprovider is not None:
        geoprovider_entry.insert(0, geoprovider)
    else:
        geoprovider_entry.insert(0, "Empty")  # Set a default value or empty string


    def select_folder():
        folder_path = filedialog.askdirectory()
        if folder_path:
            filepath_entry.delete(0, tk.END)
            filepath_entry.insert(0, folder_path)


    # FILE PATH GUI ENTRY
    filepath_frame = ttk.LabelFrame(general_tab, text="File Export Path")
    filepath_frame.grid(padx=10, pady=5, column=2)
    filepath_entry = ttk.Entry(filepath_frame, width=15)
    filepath_entry.grid(padx=10, pady=10, row=1, column=1)
    filepath_entry.bind("<Return>", save_config)
    subfolder_name = config['GENERAL']['filepath']
    if subfolder_name is not None:
        filepath_entry.insert(0, subfolder_name)
    else:
        filepath_entry.insert(0, "Empty")  # Set a default value or empty string
    select_folder_button = ttk.Button(filepath_frame, text="📁Folder...", command=select_folder)
    select_folder_button.grid(row=1, column=2, padx=5, pady=5)

    save_config_button = ttk.Button(general_tab, text="Save Configuration",
                                   command=save_config)
    save_config_button.grid(padx=10, pady=5, column=1, columnspan=3, sticky="s")


    def handle_theme_light_change():
        if light_theme_var.get():
            dark_theme_var.set(False)

    def handle_theme_dark_change():
        if dark_theme_var.get():
            light_theme_var.set(False)

    theme_frame = ttk.Frame(ui_tab, style='Card.TFrame')
    theme_frame.grid(row=1, columnspan=2, sticky="nw", padx=25, pady=10)
    theme_label = ttk.Label(theme_frame, text="Set Default Theme")
    theme_label.grid(row=0, column=1, padx=10, pady=2, columnspan=2)
    light_theme_var = tk.BooleanVar(value=config['GENERAL'].getboolean('lighttheme', False))
    light_radiobutton = ttk.Radiobutton(theme_frame, style="TRadiobutton", text="Light Theme",
                                        variable=light_theme_var, value=True, command=handle_theme_light_change)
    light_radiobutton.grid(row=1, column=1, padx=10, pady=10)
    dark_theme_var = tk.BooleanVar(value=config['GENERAL'].getboolean('darktheme', False))
    dark_radiobutton = ttk.Radiobutton(theme_frame, text="Dark Theme", variable=dark_theme_var, value=True,
                                      command=handle_theme_dark_change)
    dark_radiobutton.grid(row=1, column=2, padx=10, pady=5)
    changetheme = ttk.Button(theme_frame, text="Change theme now!", command=change_theme)
    changetheme.grid(padx=10, pady=10, row=2, column=1, columnspan=2)
    cache_frame = ttk.Frame(ui_tab, style='Card.TFrame')
    cache_frame.grid(row=2, columnspan=2, padx=10, pady=10)
    cache_label = ttk.Label(cache_frame, text="Cache Options")
    cache_label.grid(row=0, column=1, padx=10, pady=2, columnspan=2)
    cache_var = tk.BooleanVar(value=config['GENERAL'].getboolean('cachemode', False))
    cache_checkbox = ttk.Checkbutton(cache_frame, text="Cache Mode", variable=cache_var)
    cache_checkbox.grid(row=3, column=1, padx=10, sticky="w")
    delete_cache_button = ttk.Button(cache_frame, text="Delete Cache",
                                     command=delete_cache_folder)
    delete_cache_button.grid(padx=10, pady=5, row=4, columnspan=2, sticky="s")
    ui_save_config_button = ttk.Button(ui_tab, text="Save Configuration",
                                       command=save_config)
    ui_save_config_button.grid(padx=10, pady=5, row=3, columnspan=2, sticky="s")
    # EMAIL RECIPIENT GUI ENTRY
    recipient_frame = ttk.LabelFrame(email_tab, text="Email Recipient")
    recipient_frame.grid(padx=20, pady=10, column=1, columnspan=3)
    recipient_entry = ttk.Entry(recipient_frame, width=30)
    recipient_entry.grid(padx=10, pady=10)
    recipient_entry.bind("<Return>", save_config)
    recipient = config['EMAIL']['recipient_email']
    recipient_entry.insert(0, recipient)
    # EMAIL SENDER GUI ENTRY
    sender_frame = ttk.LabelFrame(email_tab, text="Email Sender")
    sender_frame.grid(padx=10, pady=10, column=2)
    sender_entry = ttk.Entry(sender_frame, width=30)
    sender_entry.grid(padx=10, pady=10)
    sender_entry.bind("<Return>", save_config)
    sender = config['EMAIL']['sender_email']
    sender_entry.insert(0, sender)
    # EMAIL SUBJECT ENTRY
    subject_frame = ttk.LabelFrame(email_tab, text="Email Subject")
    subject_frame.grid(padx=10, pady=10, column=2)
    subject_entry = ttk.Entry(subject_frame, width=30)
    subject_entry.grid(padx=10, pady=10)
    subject_entry.bind("<Return>", save_config)
    subject = config['EMAIL']['subject']
    subject_entry.insert(0, subject)
    # EMAIL BODY ENTRY
    body_frame = ttk.LabelFrame(email_tab, text="Email Body")
    body_frame.grid(padx=10, pady=10, column=2)
    body_entry = tk.Text(body_frame, width=30, height=8)
    body_entry.grid(padx=10, pady=10)
    body = config['EMAIL']['body']
    body_entry.insert("1.0", body)
    email_save_config_button = ttk.Button(email_tab, text="Save Configuration",
                                   command=save_config)
    email_save_config_button.grid(padx=10, pady=5, column=1, columnspan=3, sticky="s")
    smtp_encryption_frame = ttk.LabelFrame(smtp_tab, text="SMTP Encryption")

    def handle_starttls_change():
        if starttls_var.get():
            ssl_var.set(False)

    def handle_ssl_change():
        if ssl_var.get():
            starttls_var.set(False)

    smtp_encryption_frame.grid(padx=10, pady=10, column=1, columnspan=3, sticky="n")
    starttls_var = tk.BooleanVar(value=config['SMTP'].getboolean('starttls', False))
    starttls_radiobutton = ttk.Radiobutton(smtp_encryption_frame, style="TRadiobutton", text="StartTLS", variable=starttls_var, value=True, command=handle_starttls_change)
    starttls_radiobutton.grid(row=0, column=1, padx=10)

    ssl_var = tk.BooleanVar(value=config['SMTP'].getboolean('ssl', False))
    ssl_radiobutton = ttk.Radiobutton(smtp_encryption_frame, text="SSL", variable=ssl_var, value=True,
                                      command=handle_ssl_change)
    ssl_radiobutton.grid(row=0, column=2, padx=10)
    # SMTP SERVER ENTRY
    smtp_server_frame = ttk.LabelFrame(smtp_tab, text="SMTP Server")
    smtp_server_frame.grid(padx=20, pady=10, column=1, columnspan=3)
    smtp_server_entry = ttk.Entry(smtp_server_frame, width=30)
    smtp_server_entry.grid(padx=10, pady=10)
    smtp_server_entry.bind("<Return>", save_config)
    smtp_server = config['SMTP']['smtp_server']
    smtp_server_entry.insert(0, smtp_server)
    # SMTP PORT ENTRY
    smtp_port_frame = ttk.LabelFrame(smtp_tab, text="SMTP Port")
    smtp_port_frame.grid(padx=10, pady=10, column=1, columnspan=3)
    smtp_port_entry = ttk.Entry(smtp_port_frame, width=30)
    smtp_port_entry.grid(padx=10, pady=10)
    smtp_port_entry.bind("<Return>", save_config)
    smtp_port = config['SMTP']['smtp_port']
    smtp_port_entry.insert(0, smtp_port)
    # SMTP username ENTRY
    smtp_username_frame = ttk.LabelFrame(smtp_tab, text="SMTP Username")
    smtp_username_frame.grid(padx=10, pady=10, column=1, columnspan=3)
    smtp_username_entry = ttk.Entry(smtp_username_frame, width=30)
    smtp_username_entry.grid(padx=10, pady=10)
    smtp_username_entry.bind("<Return>", save_config)
    smtp_username = config['SMTP']['smtp_username']
    smtp_username_entry.insert(0, smtp_username)
    # SMTP Password ENTRY
    smtp_password_frame = ttk.LabelFrame(smtp_tab, text="SMTP Password")
    smtp_password_frame.grid(padx=10, pady=10, column=1, columnspan=3)
    smtp_password_entry = ttk.Entry(smtp_password_frame, width=30)
    smtp_password_entry.grid(padx=10, pady=10)
    smtp_password_entry.bind("<Return>", save_config)
    smtp_password = load_decrypted_data('arg', 'smtp_password')
    if smtp_password is not None:
        smtp_password_entry.insert(0, smtp_password)
    else:
        smtp_password_entry.insert(0, "Empty")  # Set a default value or empty string
    smtp_save_config_button = ttk.Button(smtp_tab, text="Save Configuration",
                                         command=save_config)
    smtp_save_config_button.grid(padx=10, pady=10, column=1, columnspan=3, sticky="s")

    task_scheduler_button = ttk.Button(cli_tab, text="Task Scheduler",
                                       command=open_task_scheduler)
    task_scheduler_button.grid(padx=5, pady=5, row=1, column=1, sticky="n")
    open_cmd_button = ttk.Button(cli_tab, text="CMD",
                                 command=open_cmd_at_executable_path)
    open_cmd_button.grid(padx=5, pady=5, row=1, column=2, sticky="n")
    scheduler_explanation_frame1 = ttk.LabelFrame(cli_tab, text="Base Options")
    scheduler_explanation_frame1.grid(padx=10, pady=2, row=2, column=1, columnspan=2)
    scheduler_explanation_label1 = ttk.Label(scheduler_explanation_frame1, text="--cli (required) | --agents | --snmp |\n--tcp | --http | --configure")
    scheduler_explanation_label1.grid(padx=10, pady=5, column=1, columnspan=3)
    scheduler_explanation_frame2 = ttk.LabelFrame(cli_tab, text="Agents Options")
    scheduler_explanation_frame2.grid(padx=10, pady=2, row=3, column=1, columnspan=2)
    scheduler_explanation_label2 = ttk.Label(scheduler_explanation_frame2, text="--customername | --devicename | --lanip"
                                                                                " \n --ostype | --serialnumber | --vendor"
                                                                                " \n --wanip | --domain | --username | --model "
                                                                                "\n --processor --cores --os")
    scheduler_explanation_label2.grid(padx=10, pady=5, column=1, columnspan=3)
    scheduler_explanation_frame3 = ttk.LabelFrame(cli_tab, text="SNMP Options")
    scheduler_explanation_frame3.grid(padx=10, pady=2, row=4, column=1, columnspan=2)
    scheduler_explanation_label3 = ttk.Label(scheduler_explanation_frame3, text="--customername | --devicename | --deviceid "
                                                                                "\n--hostname | --type")
    scheduler_explanation_label3.grid(padx=10, pady=5, column=1, columnspan=3)
    scheduler_explanation_frame4 = ttk.LabelFrame(cli_tab, text="TCP Options")
    scheduler_explanation_frame4.grid(padx=10, pady=2, row=5, column=1, columnspan=2)
    scheduler_explanation_label4 = ttk.Label(scheduler_explanation_frame4, text="--customername | --devicename | --deviceid "
                                                                                "\n--portnumber | --hostname")
    scheduler_explanation_label4.grid(padx=10, pady=5, column=1, columnspan=3)
    scheduler_explanation_frame5 = ttk.LabelFrame(cli_tab, text="HTTP Options")
    scheduler_explanation_frame5.grid(padx=10, pady=2, row=6, column=1, columnspan=2)
    scheduler_explanation_label5 = ttk.Label(scheduler_explanation_frame5, text="--customername | --devicename | --deviceid "
                                                                                "\n--url | --pattern")
    scheduler_explanation_label5.grid(padx=10, pady=5, column=1, columnspan=3)
    scheduler_explanation_frame6 = ttk.LabelFrame(cli_tab, text="Report Options")
    scheduler_explanation_frame6.grid(padx=10, pady=2, row=7, column=1, columnspan=2)
    scheduler_explanation_label6 = ttk.Label(scheduler_explanation_frame6, text="--pdf | --csv | --email | --teams")
    scheduler_explanation_label6.grid(padx=10, pady=5, column=1, columnspan=3)
    # Create a radio button for each search option
    num_options = len(searchops.options('SNMPSearchOptions'))
    options_per_column = min(num_options, 10)
    options_remaining = num_options
    for i, option in enumerate(searchops.options('SNMPSearchOptions')):
        snmp_option_var = tk.StringVar()
        snmp_option_var.set(searchops['SNMPSearchOptions'][option])
        snmp_option_label = ttk.Label(snmp_frame, text=option)
        snmp_option_label.grid(row=i, column=0, padx=5, pady=5, sticky="w")

        snmp_value_entry = ttk.Entry(snmp_frame)
        snmp_value_entry.grid(row=i, column=1, padx=5, pady=5)
        snmp_value_entry.bind("<Return>", search_button_clicked)
        snmp_option_vars.append(snmp_option_var)
        snmp_value_entries.append(snmp_value_entry)
    # Add more radio buttons for other search options
    # Create a frame for the Information

        # Create a frame for the search option
    http_search_option_frame = ttk.LabelFrame(http_frame, text="Search Options")
    http_search_option_frame.grid(padx=10, pady=10)
    # Create a radio button for each search option
    num_options = len(searchops.options('HTTPSearchOptions'))
    options_per_column = min(num_options, 10)
    options_remaining = num_options
    for i, option in enumerate(searchops.options('HTTPSearchOptions')):
        http_option_var = tk.StringVar()
        http_option_var.set(searchops['HTTPSearchOptions'][option])
        http_option_label = ttk.Label(http_frame, text=option)
        http_option_label.grid(row=i, column=0, padx=5, pady=5, sticky="w")

        http_value_entry = ttk.Entry(http_frame)
        http_value_entry.grid(row=i, column=1, padx=5, pady=5)
        http_value_entry.bind("<Return>", search_button_clicked)
        http_option_vars.append(http_option_var)
        http_value_entries.append(http_value_entry)

    tcp_search_option_frame = ttk.LabelFrame(tcp_frame, text="Search Options")
    tcp_search_option_frame.grid(padx=10, pady=10)
    # Create a radio button for each search option
    num_options = len(searchops.options('TCPSearchOptions'))
    options_per_column = min(num_options, 10)
    options_remaining = num_options

    for i, option in enumerate(searchops.options('TCPSearchOptions')):
        tcp_option_var = tk.StringVar()
        tcp_option_var.set(searchops['TCPSearchOptions'][option])
        tcp_option_label = ttk.Label(tcp_frame, text=option)
        tcp_option_label.grid(row=i, column=0, padx=5, pady=5, sticky="w")

        tcp_value_entry = ttk.Entry(tcp_frame)
        tcp_value_entry.grid(row=i, column=1, padx=5, pady=5)
        tcp_value_entry.bind("<Return>", search_button_clicked)
        tcp_option_vars.append(tcp_option_var)
        tcp_value_entries.append(tcp_value_entry)

    # Create a search button

    custom_font = font.Font(size=16)
    search_button = tk.Button(big_content_frame, command=search_button_clicked,
                              width=200, height=50, font=custom_font, relief=tk.FLAT, bd=0)
    search_button.grid(padx=10, pady=10, row=4, column=1, columnspan=2)
    images_folder = "images"
    searchbutton_path = generate_img

    button_image = tk.PhotoImage(file=searchbutton_path)
    resized_image = button_image.subsample(4)  # Resize the image by a factor of 2
    search_button.config(image=resized_image, compound=tk.CENTER)

    # Start the main loop
    window.mainloop()
