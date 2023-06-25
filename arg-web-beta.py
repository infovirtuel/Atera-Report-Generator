import requests
import json
import csv
import configparser
import datetime
from tkinter import filedialog
import os
import itertools
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table , TableStyle, Image as pdf_image, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import sys
import ssl
import ast
from tqdm import tqdm
import pandas as pd
import subprocess
import shutil
import traceback
from nicegui import ui, app
import socket
from nicegui.events import ValueChangeEventArguments


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # doesn't even have to be reachable
        s.connect(('10.254.254.254', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP
script_path = os.path.dirname(os.path.abspath(__file__))
report_path = os.path.join(script_path, "reports")
os.makedirs(report_path, exist_ok=True)

app.add_static_files('/reports', "reports")


base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
icon_img = os.path.join(base_path, 'source', 'images', 'arg2.svg')
generate_img = os.path.join(base_path, 'source', 'images', 'generate2.png')
logo_img = os.path.join(base_path, 'source', 'images', 'banner3.png')
config_file = 'config.ini'
searchops_file = 'searchops.ini'




if not os.path.exists(config_file):
    with open(config_file, 'w') as file:
        file.write('')  # You can add initial contents if needed

if not os.path.exists(searchops_file):
    with open(searchops_file, 'w') as file:
        file.write('')  # You can add initial contents if needed


config = configparser.ConfigParser()
searchops = configparser.ConfigParser()
snmp_searchops = configparser.ConfigParser()
config.read('config.ini')
searchops.read('searchops.ini')
output_mode = None
chosen_eol_date = None
base_url = "https://app.atera.com/api/v3/"
devices_endpoint = "agents"
snmp_devices_endpoint = "devices/snmpdevices"
http_devices_endpoint = "devices/httpdevices"
tcp_devices_endpoint = "devices/tcpdevices"
endoflife_url = "https://endoflife.date/api/"
endoflife_windows_endpoint = "windows.json"
endoflife_windows_server_endpoint = "windowsserver.json"
endoflife_macos_endpoint = "macos.json"
endoflife_ubuntu_endpoint = "ubuntu.json"
endoflife_intel_endpoint = "intel-processors.json"
ip_api_url = config['GENERAL']['geolocation_provider']

def make_endoflife_request(endpoint, method="GET", params=None):
    url = endoflife_url + endpoint
    headers = {
        "Accept": "application/json",
    }

    response = requests.request(method, url, headers=headers, params=params)
    response.raise_for_status()
    return response.json()


def make_atera_request(endpoint, method="GET", params=None):

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
        config['GENERAL']['cachemode'] = "True"
    if 'excel_output' not in config['GENERAL']:
        config['GENERAL']['excel_output'] = "False"
        # Config File Sanitation
    onlineonly_sanitation = config['GENERAL']['onlineonly']
    geolocation_sanitation = config['GENERAL']['geolocation']
    eol_sanitation = config['GENERAL']['eol']
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
    if not port_sanitation.isnumeric():
        config['SMTP']['smtp_port'] = "587"
    if "@" not in sender_sanitation:
        config['EMAIL']['sender_email'] = "defaultsender@default.com"
    if "@" not in recipient_sanitation:
        config['EMAIL']['recipient_email'] = "defaultrecipient@default.com"
    if not geoprovider_sanitation.startswith("http://") and not geoprovider_sanitation.startswith("https://"):
        config['GENERAL']['geolocation_provider'] = "https://api.techniknews.net/ipgeo/"

    # ip-api.com API

with open('config.ini', 'w') as configfile:
    config.write(configfile)
create_config()


def make_geolocation_request(device_wan_ip, method="GET", params=None):
    geolocationurl = ip_api_url + device_wan_ip
    headers = {
        "Accept": "application/json",
    }

    response = requests.request(method, geolocationurl, headers=headers, params=params)
    response.raise_for_status()
    return response.json()


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
        chosen_eol_date = None
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
        #chosen_eol_date = None
        if eolreport:
            try:
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

                if device_os is not None and ('Windows 11' in device_os or 'Windows 10' in device_os or 'Windows 7' in device_os or \
                        'Windows 8' in device_os or 'Windows 8.1' in device_os):
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

                elif device_os is not None and 'Server' in device_os:

                    if eol_response1 is not None and isinstance(eol_response1, list):
                        for item in eol_response1:
                            api_windows_srv_version = item["cycle"]
                            api_srv_eol_date = item["eol"]

                            if api_windows_srv_version in device_os:
                                chosen_eol_date = api_srv_eol_date
                                break

                elif device_os is not None and 'macOS' in device_os:
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

            except Exception as e:
                traceback.print_exc()
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

        ui.notify(f"Email from {sender_result} sent successfully to {recipient_result}", type='positive')

    except smtplib.SMTPException as e:
        ui.notify({str(e)}, type='negative')


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
    teams_webhook = config['GENERAL']['teams_webhook']
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
    doc = SimpleDocTemplate(pdf_filename, pagesize=letter)

    # Set up styles for the document
    styles = getSampleStyleSheet()
    title_style = styles['Title']
    header_style = ParagraphStyle(
        'Heading1',
        parent=styles['Heading1'],
        alignment=1,  # Center alignment
        underline=False,  # Disable underline
    )

    normal_style = styles['Normal']
    table_style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), '#FF176B'),  # Header background color
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),  # Header text color
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),  # Content background color
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ])

    # Create the story to hold the document content
    story = []
    current_year = datetime.datetime.now().year
    current_month = datetime.datetime.now().month
    current_day = datetime.datetime.now().day
    pdf_img = pdf_image(logo_img, width=6*inch, height=0.75*inch)
    header_text = f"Report Generated on {current_day}-{current_month}-{current_year}"
    header_paragraph = Paragraph("<span>{}</span>".format(header_text), header_style)

    container_table_data = [
        [pdf_img],
        [header_paragraph],
    ]
    container_table = Table(container_table_data, colWidths=[6 * inch])
    container_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),  # Center the content horizontally within the container table
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),  # Center the content vertically within the container table
        ('GRID', (0, 0), (-1, -1), 0.5, '#FF176B'),  # Add borders to the container table
    ]))

    story.append(Spacer(1, 12))
    story.append(container_table)
    story.append(Spacer(1, 12))
    try:
        for device in found_devices:
            data = []

            if output_mode == "agents":
                data = extract_device_information(device, output_mode)
                freedisk = data[20]
                if data[20] is None:
                    freedisk = 0
                useddisk = data[21]
                if data[21] is None:
                    useddisk = 0
                totaldisk = data[22]
                if data[22] is None:
                    totaldisk = 0
                percentdisk = data[23]
                if data[23] is None:
                    percentdisk = 0

                general_section = [
                    ["Device Name:", str(data[0])],
                    ["Device Company:", str(data[1])],
                    ["Device Domain:", str(data[2])],
                    ["Username:", str(data[9])],
                ]
                second_section = [
                    ["OS:", str(data[3])],
                    ["OS Version:", str(data[4])],
                    ["OS Serial Number:", str(data[12])],
                    ["EOL Status:", str(data[26])],
                    ["Device Type:", str(data[5])],
                    ["Vendor:", str(data[15])],
                    ["Model:", str(data[16])],
                    ["Serial Number:", str(data[11])],
                    ["Online Status:", 'Online' if data[8] else 'Offline'],
                    ["Last Reboot:", str(data[10])],
                    ["LAN IP:", str(data[6])],
                    ["WAN IP:", str(data[7])],
                    ["Geolocation:", str(data[24])],
                    ["ISP:", str(data[25])],
                    ["Processor:", str(data[13])],
                    ["RAM:", f"{data[14]:.2f} GB"],
                    #["GPU:", str(data[17])],
                    ["C: Free Disk Space:", f"{freedisk:.2f} GB"],
                    ["C: Used Disk Space:", f"{useddisk:.2f} GB"],
                    ["C: Total Disk Space:", f"{totaldisk:.2f} GB"],
                    ["C: Disk Usage:", f"{percentdisk:.2f} %"]

                ]
            if output_mode == "tcp":
                data = extract_device_information(device, output_mode)
                table_data = [
                    ["Device Name:", str(data[0])],
                    ["Device Company:", str(data[2])],
                    ["Online Status:", 'Online' if data[3] else 'Offline'],
                    ["Device ID:", str(data[1])],
                    ["TCP Port:", str(data[4])],
                ]
            if output_mode == "snmp":
                data = extract_device_information(device, output_mode)
                table_data = [
                    ["Device Name:", str(data[0])],
                    ["Device Company:", str(data[2])],
                    ["Device ID:", str(data[1])],
                    ["Online Status:", 'Online' if data[4] else 'Offline'],
                    ["Hostname:", str(data[3])],
                    ["Type:", str(data[5])],
                    ["Security:", str(data[6])],
                ]
            if output_mode == "http":
                data = extract_device_information(device, output_mode)
                table_data = [
                    ["Device Name:", str(data[0])],
                    ["Device Company:", str(data[2])],
                    ["Device ID:", str(data[1])],
                    ["Online Status:", 'Online' if data[4] else 'Offline'],
                    ["URL:", str(data[3])],
                    ["Pattern:", str(data[5])],
                    ["Pattern Status:", 'OK' if data[6] else 'Error'],
                ]




            # Add device information to the content list
            if data:
                story.append(Spacer(1, 12))

                # Create the table for device information
                if not output_mode == "agents":
                    table = Table(table_data, colWidths=[2 * inch, 4 * inch])
                    table.setStyle(table_style)
                    story.append(table)
                    story.append(Spacer(1, 30))
                else:
                    table_data = general_section + second_section
                    table = Table(table_data, colWidths=[2 * inch, 4 * inch])
                    table.setStyle(table_style)
                    section = [Spacer(1, 12),
                               KeepTogether(table),
                               Spacer(1, 30)]
                    story.extend(section)

        doc.build(story)
    except Exception as e:
        traceback.print_exc()


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

        ui.notify( str(e), type='negative')


# Function to handle the search button click event


def output_results(found_devices, cli_mode,
                   teams_output, csv_output, pdf_output, email_output, search_values, output_mode):
    ipadd = get_ip()

    config.read('config.ini')
    csv_filename = None
    excel_filename = None
    pdf_filename = None
    csv_download = None
    pdf_download = None
    excel_download = None
    excel_output = config['GENERAL']['excel_output']
    current_datetime = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    script_path = os.path.dirname(os.path.abspath(__file__))
    report_path = os.path.join(script_path, "reports")
    os.makedirs(report_path, exist_ok=True)

    if not os.path.exists(report_path):
        os.makedirs(report_path)
    pdf_download = f"{output_mode}_pdf_report_{current_datetime}.pdf"
    csv_download = f"{output_mode}_csv_report_{current_datetime}.csv"
    excel_download = f"{output_mode}_excel_report_{current_datetime}.xlsx"
    pdf_filename = os.path.join(report_path, f"{pdf_download}")
    csv_filename = os.path.join(report_path, f"{csv_download}")
    excel_filename = os.path.join(report_path, f"{excel_download}")

    if pdf_output:

        pdf_results(found_devices, pdf_filename, cli_mode, output_mode)

    if csv_output:
        csv_results(found_devices, csv_filename, cli_mode, output_mode)

        if excel_output:
            if excel_output == "True":

                csv_encoding = 'latin-1'
                data = pd.read_csv(csv_filename, encoding=csv_encoding)
                data.to_excel(excel_filename, index=False, )

    if pdf_output:
        ui.download(f'http://{ipadd}:8080/reports/{pdf_download}')
    if csv_output:
        ui.download(f'http://{ipadd}:8080/reports/{csv_download}')
        if excel_output:
            ui.download(f'http://{ipadd}:8080/reports/{excel_download}')

    if teams_output:
        teams_results(found_devices, search_values, output_mode, cli_mode)

    if email_output:
        email_results(csv_output, pdf_output, csv_filename, pdf_filename, cli_mode, excel_filename)
    # Display the results in a new window


def get_params():
    search_options = []
    search_values = []
    output_mode_query = output_mode
    csv_output_query = csv_output.value
    pdf_output_query = pdf_output.value
    teams_output_query = teams_output.value
    email_output_query = email_output.value
    devicename_query = device_input.value
    customername_query = company_input.value
    serialnumber_query = serialnumber_input.value
    lanip_query = lanip_input.value
    ostype_query = ostype_input.value
    vendor_query = vendor_input.value
    username_query = username_input.value
    wanip_query = wanip_input.value
    domainname_query = domainname_input.value
    model_query = model_input.value
    processor_query = processor_input.value
   # core_query = core_input.value
    osversion_query = osversion_input.value

    if csv_output_query != 'false' and pdf_output_query != 'false' and teams_output_query != 'false':
        if devicename_query != '':
            search_options.append('Device Name')
            search_values.append(devicename_query)
        if customername_query != '':
            search_options.append('Company')
            search_values.append(customername_query)
        if serialnumber_query != '':
            search_options.append('Serial Number')
            search_values.append(serialnumber_query)
        if lanip_query != '':
            search_options.append('Serial Number')
            search_values.append(lanip_query)
        if ostype_query != '':
            search_options.append('OS Type')
            search_values.append(ostype_query)
        if vendor_query != '':
            search_options.append('Vendor')
            search_values.append(vendor_query)
        if username_query != '':
            search_options.append('Username')
            search_values.append(username_query)
        if wanip_query != '':
            search_options.append('WAN IP')
            search_values.append(wanip_query)
        if domainname_query != '':
            search_options.append('Domain Name')
            search_values.append(domainname_query)
        if model_query != '':
            search_options.append('Vendor Model')
            search_values.append(model_query)
        if processor_query != '':
            search_options.append('Processor')
            search_values.append(processor_query)
       # if core_query is not None:
       #     search_options.append('Core Amount')
       #     search_values.append(core_query)
        if osversion_query != '':
            search_options.append('OS VERSION')
            search_values.append(osversion_query)
        print(search_values)
        print(search_options)
        fetch_device_information(search_options, search_values, teams_output=teams_output_query,
                                 csv_output=csv_output_query, email_output=email_output_query, pdf_output=pdf_output_query, cli_mode=False,
                                 output_mode="agents", endpoint=devices_endpoint)
    else:
        with ui.dialog() as dialog, ui.card():
            ui.label('Hello world!')
            ui.button('Close', on_click=dialog.close)


def delete_cache_folder():
    cache_directory = "arg_cache"

    # Check if cache directory exists
    if os.path.exists(cache_directory):
        # Remove the cache directory and all its contents
        shutil.rmtree(cache_directory)
        ui.notify('Successfully flushed cached files', type='positive')
    else:
        ui.notify('No Cache Available', type='warning')


def save_config(event=None):

    def save_general_config():
        save_api_key = apikey.value
        save_teams_webhook = webhook.value
        save_geolocation = geolocation.value
        save_geoprovider = geoprovider.value
        save_eol = oseol.value
        save_onlineonly = online_only.value
        save_excel = xlsx_export.value
        save_cache_mode = cache_mode.value
        config['GENERAL'] = {
            'api_key': save_api_key,
            'teams_webhook': save_teams_webhook,
            'geolocation': save_geolocation,
            'geolocation_provider': save_geoprovider,
            'eol': save_eol,
            'onlineonly': save_onlineonly,
            'excel_output': save_excel,
            'cachemode': save_cache_mode,



        }
        with open('config.ini', 'w') as configfile:
            config.write(configfile)
        ui.notify('Successfully Saved Configuration', type='positive')

    def save_email_config():
        save_email_sender = emailsender.value
        save_email_recipient = emailrecipient.value
        save_email_subject = emailsubject.value
        save_email_body = emailbody.value


        config['EMAIL'] = {
            'sender_email': save_email_sender,
            'recipient_email': save_email_recipient,
            'subject': save_email_subject,
            'body': save_email_body

        }
        with open('config.ini', 'w') as configfile:
            config.write(configfile)

    def save_smtp_config():
        save_smtp_server = smtpserver.value
        save_smtp_port = smtpport.value
        save_smtp_username = smtpusername.value
        save_smtp_password = smtppassword.value
        save_starttls = starttls.value
        save_ssl = ssl.value

        config['SMTP'] = {
            'smtp_server': save_smtp_server,
            'smtp_port': save_smtp_port,
            'smtp_username': save_smtp_username,
            'smtp_password': save_smtp_password,
            'starttls': save_starttls,
            'ssl': save_ssl
        }
        with open('config.ini', 'w') as configfile:
            config.write(configfile)

    save_smtp_config()
    save_email_config()
    save_general_config()


with ui.header(elevated=True).style('background-color: #FF176B').classes('justify-center'):

    #ui.label('').classes('self-center').classes('order-2 font-black')
    ui.image(logo_img).classes('max-w-md self-center order-3')
    #ui.label('Atera Report Generator').classes('self-center').classes('order-3')
    ui.button(on_click=lambda: right_drawer.toggle(), icon='settings').props('flat color=white').classes('order-4 self-center justify-end')


with ui.right_drawer(fixed=False).style('background-color: #ebf1fa').props('bordered overlay=True').classes('') as right_drawer:

    saved_geolocation_option = config['GENERAL']['geolocation']
    saved_onlineonly_option = config['GENERAL']['onlineonly']
    saved_apikey_option = config['GENERAL']['api_key']
    saved_webhook_option = config['GENERAL']['teams_webhook']
    saved_eol_option = config['GENERAL']['eol']
    saved_excel_option = config['GENERAL']['excel_output']
    saved_cache_mode = config['GENERAL']['cachemode']
    saved_geoprovider_option = config['GENERAL']['geolocation_provider']
    saved_email_recipient = config['EMAIL']['recipient_email']
    saved_email_sender = config['EMAIL']['sender_email']
    saved_email_subject = config['EMAIL']['subject']
    saved_email_body = config['EMAIL']['body']
    saved_smtp_server = config['SMTP']['smtp_server']
    saved_smtp_port = config['SMTP']['smtp_port']
    saved_smtp_username = config['SMTP']['smtp_username']
    saved_smtp_password = config['SMTP']['smtp_password']
    saved_ssl_option = config['SMTP']['ssl']
    saved_starttls_option = config['SMTP']['starttls']

    ui.label('General Options')
    with ui.splitter(horizontal=True) as splitter:
        with splitter.before:
            apikey = ui.input(label='Atera API Key', placeholder='Insert API Key',
                                    validation={'Input too long': lambda value: len(value) < 100}).bind_value(globals(), 'saved_apikey_option').classes('q-mb-md')
            webhook = ui.input(label='Webhook URL', placeholder='https://......',
                                    validation={'Input too long': lambda value: len(value) < 500}).bind_value(globals(), 'saved_webhook_option').classes('q-mb-md')
            geoprovider = ui.input(label='Geolocation Provider', placeholder='https://....',
                                    validation={'Input too long': lambda value: len(value) < 60}).bind_value(globals(), 'saved_geoprovider_option').classes('q-mb-md')

            ui.label('Advanced Report Options')
            with ui.row():
                oseol = ui.checkbox('OS EOL')
                geolocation = ui.checkbox('Geolocation').bind_value(globals(), 'saved_geolocation_option')
            with ui.row():
                online_only = ui.checkbox('Online Devices').bind_value(globals(), 'saved_onlineonly_option')
                xlsx_export = ui.checkbox('Excel File').bind_value(globals(), 'saved_excel_option')
            with ui.row():
                cache_mode = ui.checkbox('Cache Mode').bind_value(globals(), 'saved_cache_mode')

        with splitter.after:
            ui.label('Email Options')
            emailrecipient = ui.input(label='Email Recipient', placeholder='recipient@something.com',
                              validation={'Input too long': lambda value: len(value) < 100}).bind_value(globals(),'saved_email_recipient').classes('q-mb-md')
            emailsender = ui.input(label='Email Sender', placeholder='sender@something.com',
                              validation={'Input too long': lambda value: len(value) < 100}).bind_value(globals(),'saved_email_sender').classes('q-mb-md')
            emailsubject = ui.input(label='Email Subject', placeholder='Atera Report Results',
                              validation={'Input too long': lambda value: len(value) < 100}).bind_value(globals(),'saved_email_subject').classes('q-mb-md')

            emailbody = ui.textarea(label='Email Body', placeholder='Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt',validation={'Input too long': lambda value: len(value) < 100}).bind_value(globals(),'saved_email_body').classes('q-mb-md')
    with ui.splitter(horizontal=True) as splitter:
        with splitter.before:
            smtpserver = ui.input(label='SMTP Server', placeholder='smtp.office365.com',validation={'Input too long': lambda value: len(value) < 100}).bind_value(globals(),'saved_smtp_server').classes('q-mb-md')
            smtpport = ui.input(label='SMTP Port', placeholder='587',validation={'Input too long': lambda value: len(value) < 100}).bind_value(globals(),'saved_smtp_port').classes('q-mb-md')
            with ui.row():
                ssl = ui.checkbox('SSL').bind_value(globals(), 'saved_ssl_option')
                starttls = ui.checkbox('TLS').bind_value(globals(), 'saved_starttls_option')

            smtpusername = ui.input(label='SMTP Username', placeholder='sender@something.com',validation={'Input too long': lambda value: len(value) < 100}).bind_value(globals(),'saved_smtp_username').classes('q-mb-md')
            smtppassword = ui.input(label='SMTP Password', placeholder='Enter your Password Here',validation={'Input too long': lambda value: len(value) < 100}).bind_value(globals(),'saved_smtp_password').classes('q-mb-md')




            cache_flush = ui.button('Flush Cache', on_click=delete_cache_folder, icon='cached').classes('q-mt-md')
            save_config_button = ui.button('Save Configuration', on_click=save_config, icon='save').classes('q-mt-md')
    #Report Options
        #OS End of Life
        #Geolocation
        #Online Devices
        #XLSX Files
    #Geolocation Provider
    #File Export Path
    #Cache Option
    #ui.label('Email Options')

    #ui.label('SMTP Options')


    #ui.image(logo_img)
#ui.image(logo_img).classes('max-w-md self-center')
with ui.tabs().classes('w-full') as tabs:
    one = ui.tab('Agent Devices', label='Agent Devices', icon='computer').classes('q-px-lg')
    two = ui.tab('S', label='SNMP Devices', icon='dns')
    three = ui.tab('T', label='TCP Devices', icon='lan')
    four = ui.tab('H', label='HTTP Devices', icon='language')

with ui.tab_panels(tabs, value=one).classes('self-center w-full'):
    with ui.tab_panel(one):
        with ui.splitter().classes('self-center') as splitter:
            with splitter.before:
                device_input = ui.input(label='Device Name', placeholder='start typing',
                                        validation={'Input too long': lambda value: len(value) < 60}).classes('mr-2')
                company_input = ui.input(label='Customer', placeholder='start typing',
                                         validation={'Input too long': lambda value: len(value) < 60}).classes('mr-2')
                serialnumber_input = ui.input(label='Serial Number', placeholder='start typing',
                                              validation={'Input too long': lambda value: len(value) < 60}).classes('mr-2')
                lanip_input = ui.input(label='LAN IP', placeholder='start typing',
                                       validation={'Input too long': lambda value: len(value) < 60}).classes('mr-2')
                ostype_input = ui.input(label='OS Type', placeholder='start typing',
                                        validation={'Input too long': lambda value: len(value) < 60}).classes('mr-2')
                vendor_input = ui.input(label='Vendor', placeholder='start typing',
                                        validation={'Input too long': lambda value: len(value) < 60}).classes('mr-2')

            with splitter.after:
                username_input = ui.input(label='Username', placeholder='start typing',
                                          validation={'Input too long': lambda value: len(value) < 60}).classes('ml-2')
                wanip_input = ui.input(label='WAN IP', placeholder='start typing',
                                       validation={'Input too long': lambda value: len(value) < 60}).classes('ml-2')
                domainname_input = ui.input(label='Domain Name', placeholder='start typing',
                                            validation={'Input too long': lambda value: len(value) < 60}).classes('ml-2')
                model_input = ui.input(label='Model', placeholder='start typing',
                                       validation={'Input too long': lambda value: len(value) < 60}).classes('ml-2')
                processor_input = ui.input(label='Processor', placeholder='start typing',
                                           validation={'Input too long': lambda value: len(value) < 60}).classes('ml-2')
                #core_input = ui.input(label='Core Amount', placeholder='start typing',
                #                      validation={'Input too long': lambda value: len(value) < 20}).classes('ml-2')
                osversion_input = ui.input(label='Operating System', placeholder='start typing',
                                           validation={'Input too long': lambda value: len(value) < 60}).classes('ml-2')

    with ui.tab_panel(two):
        ui.label('WORK IN PROGRESS')

    with ui.tab_panel(three):
        ui.label('WORK IN PROGRESS')
    with ui.tab_panel(four):
        ui.label('WORK IN PROGRESS')
with ui.grid(columns=4).classes('self-center'):
    csv_output = ui.switch('Excel')
    pdf_output = ui.switch('PDF')
    teams_output = ui.switch('Teams')
    email_output = ui.switch('Email')



ui.button('Generate Report', on_click=get_params, icon='cloud_download').props('color=pink-5').classes('self-center')

result = ui.label()

icon = 'data:image/png;base64,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'
ui.run(title='Atera Report Generator',host='0.0.0.0', favicon=icon)
