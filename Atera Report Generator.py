import requests
import json
import csv
import tkinter as tk
import configparser
import datetime
from tkinter import messagebox
from PIL import ImageTk, Image
import os
import webbrowser
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
    output_agent_group.add_argument('--onlineonly', action='store_true', help='Online Only')
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
    output_agent_group.add_argument('--eol', action='store_true', help='EOL Report for Devices')

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
    smtp_group.add_argument('--password', help='Set the SMTP Password in the system keyring')
    smtp_group.add_argument('--port', help='Set the SMTP Port in the config.ini file')
    general_group.add_argument('--filepath', help='Set the filepath for CSV/PDF Reports in the config.ini file')
    smtp_group.add_argument('--server', help='Set the SMTP Server in config.ini')
    smtp_group.add_argument('--starttls', help='Set the StartTLS Encryption for SMTP Server in config.ini')
    smtp_group.add_argument('--ssl', help='Set the StartTLS Encryption for SMTP Server in config.ini')
    email_group.add_argument('--sender', help='Set the sender email in config.ini')
    email_group.add_argument('--recipient', help='Set the recipient email in config.ini')
    email_group.add_argument('--subject', help='Set the subject for email in config.ini')
    email_group.add_argument('--body', help='Set the body for email in config.ini')


arguments = parser.parse_args()
if arguments.cli:

    if not arguments.agents and not arguments.snmp and not arguments.configure and not arguments.http and not arguments.tcp:
        sys.exit("Error: No Report Type Selected\n You can use (-h) in the CLI to see all available options")

base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
icon_img = os.path.join(base_path, 'images', 'arg.ico')
generate_img = os.path.join(base_path, 'images', 'generate.png')
github_img = os.path.join(base_path, 'images', 'github.png')
logo_img = os.path.join(base_path, 'images', 'logo.png')


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


# Function to make an authenticated API request
def make_endoflife_request(endpoint, method="GET", params=None):
    url = endoflife_url + endpoint
    headers = {
        "Accept": "application/json",
    }

    response = requests.request(method, url, headers=headers, params=params)
    response.raise_for_status()
    return response.json()


# Function to make an authenticated API request
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
    searchops['SNMPSearchOptions']['device name'] = "Device Name"
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
    if 'filepath' not in config['GENERAL']:
        config['GENERAL']['filepath'] = ""
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

    with open('config.ini', 'w') as configfile:
        config.write(configfile)


create_config()

def extract_device_information(device, output_mode):
    if output_mode == "agents":
        device_name = device["MachineName"]
        device_company = device["CustomerName"]
        device_domain = device["DomainName"]
        device_os = device["OS"]
        device_win_version = device["OSVersion"]
        device_type = device["OSType"]
        device_ip = device["IpAddresses"]
        device_wan_ip = device["ReportedFromIP"]
        device_status = device["Online"]
        device_online = device["Online"]
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
        device_atera_url = device["AppViewUrl"]
        device_description = device["ComputerDescription"]
        c_drive_free = None
        c_drive_used = None
        c_drive_total = None
        c_drive_usage_percent = None
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

        return (device_name, device_company, device_domain, device_os, device_win_version,
                device_type, device_ip, device_wan_ip, device_status, device_currentuser,
                device_lastreboot, device_serial, device_windows_serial, device_processor,
                device_ram, device_vendor, device_model, device_gpu,
                device_os_build, device_online, c_drive_free_gb,
                c_drive_used_gb, c_drive_total_gb, c_drive_usage_percent)

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
        return (device_name, device_id, device_company, device_url, device_online, device_pattern, device_patternup)
    if output_mode == "tcp":
        device_name = device["Name"]
        device_id = device["DeviceID"]
        device_company = device["CustomerName"]
        tcp_port = [str(port['PortNumber']) for port in device['Ports']]
        device_online = [str(port['Available']) for port in device['Ports']]

        return (device_name, device_id, device_company, device_online, tcp_port)


def display_results(found_devices, output_mode):

    num_devices = len(found_devices)
    messagebox.showinfo("Devices Found", f"Number of devices found: {num_devices}")

    # Create a new window
    results_window = tk.Toplevel(window)
    results_window.iconbitmap(icon_img)
    results_window.title("Search Results")
    # Create a text widget to display the results
    results_text = tk.Text(results_window, height=40, width=80)
    results_text.grid()

    # Insert the results into the text widget
    for device in found_devices:
        if output_mode == "agents":

            device_name, device_company, device_domain, device_os, device_win_version,\
                device_type, device_ip, device_wan_ip, device_status, device_currentuser,\
                device_lastreboot, device_serial, device_windows_serial, device_processor,\
                device_ram, device_vendor, device_model, device_gpu,\
                device_os_build, device_online, c_drive_free_gb, c_drive_used_gb,\
                c_drive_total_gb, c_drive_usage_percent = extract_device_information(device, output_mode)

        if output_mode == "snmp":
            snmp_device_name, device_id, device_company, device_hostname, device_online, device_type, device_security, = extract_device_information(device, output_mode)

        if output_mode == "http":
            device_name, device_id, device_company, device_url, device_online, device_pattern, device_patternup = extract_device_information(device, output_mode)
        if output_mode == "tcp":
            device_name, device_id, device_company, device_online, tcp_port = extract_device_information(device, output_mode)

        # REGULAR DEVICES
        if device.get('MachineName'):
            results_text.insert(tk.END, f"Device Name: {device['MachineName']}\n")
        if device.get('ComputerDescription'):
            results_text.insert(tk.END, f"Description: {device['ComputerDescription']}\n")
        if device.get('DomainName'):
            results_text.insert(tk.END, f"Domain Name: {device['DomainName']}\n")
        if device.get('OS'):
            results_text.insert(tk.END, f"OS: {device['OS']}\n")
        if device.get('OSVersion'):
            results_text.insert(tk.END, f"OS Version: {device['OSVersion']}\n")
        if device.get('OSType'):
            results_text.insert(tk.END, f"OS Type: {device['OSType']}\n")
        if device.get('IpAddresses'):
            results_text.insert(tk.END, f"LAN IP: {device['IpAddresses']}\n")
        if device.get('ReportedFromIP'):
            results_text.insert(tk.END, f"WAN IP: {device['ReportedFromIP']}\n")
        if device.get('CurrentLoggedUsers'):
            results_text.insert(tk.END, f"Logged in Users: {device['CurrentLoggedUsers']}\n")
        if device.get('LastRebootTime'):
            results_text.insert(tk.END, f"Last Reboot: {device['LastRebootTime']}\n")
        if device.get('VendorSerialNumber'):
            results_text.insert(tk.END, f"Serial Number (Service tag): {device['VendorSerialNumber']}\n")
        if device.get('WindowsSerialNumber'):
            results_text.insert(tk.END, f"Windows Serial Number: {device['WindowsSerialNumber']}\n")
        if device.get('Processor'):
            results_text.insert(tk.END, f"Processor: {device['Processor']}\n")
        if device.get('Memory'):
            results_text.insert(tk.END, f"Memory: {device['Memory']}\n")
        if device.get('Vendor'):
            results_text.insert(tk.END, f"Vendor: {device['Vendor']}\n")
        if device.get('VendorBrandModel'):
            results_text.insert(tk.END, f"Model: {device['VendorBrandModel']}\n")
        if device.get('Display'):
            results_text.insert(tk.END, f"GPU: {device['Display']}\n")
        # SNMP DEVICES
        if device.get('Name'):
            results_text.insert(tk.END, f"Device Name: {device['Name']}\n")
        if device.get('DeviceID'):
            results_text.insert(tk.END, f"Device ID: {device['DeviceID']}\n")
        if device.get('Hostname'):
            results_text.insert(tk.END, f"HostName (IP): {device['Hostname']}\n")
        if device.get('Type'):
            results_text.insert(tk.END, f"Type: {device['Type']}\n")
        if device.get('SecurityLevel'):
            results_text.insert(tk.END, f"Security: {device['SecurityLevel']}\n")
        # VALID FOR ALL REPORT TYPES
        if device.get('CustomerName'):
            results_text.insert(tk.END, f"Company: {device['CustomerName']}\n")
        if device.get('Pattern'):
            results_text.insert(tk.END, f"Pattern: {device['Pattern']}\n")
        if device.get('URL'):
            results_text.insert(tk.END, f"URL: {device['URL']}\n")
        if device.get('URLUp'):
            results_text.insert(tk.END, f"Online Status: {'Online' if device['URLUp'] else 'Offline'}\n")
        if device.get('ContainsPattern'):
            results_text.insert(tk.END, f"Pattern Status: {'Pattern is present' if device['ContainsPattern'] else 'Pattern is not present'}\n")
        if output_mode == "tcp":
            if tcp_port:
                results_text.insert(tk.END, f"TCP Port: {tcp_port}\n")
            if device_online:
                results_text.insert(tk.END, f"Online Status: {'Online' if device_online else 'Offline'}\n")

        if output_mode == "agents":
            if c_drive_free_gb:
                results_text.insert(tk.END, f"C: Free Disk Space: {c_drive_free_gb:.2f} GB\n")
            if c_drive_used_gb:
                results_text.insert(tk.END, f"C: Used Disk Space: {c_drive_used_gb:.2f} GB\n")
            if c_drive_total_gb:
                results_text.insert(tk.END, f"C: Total Disk Space: {c_drive_total_gb:.2f} GB\n")

            if c_drive_usage_percent:
                results_text.insert(tk.END, f"C: Disk Usage: {c_drive_usage_percent:.2f} %\n")

        if device.get('Online'):
            results_text.insert(tk.END, f"Online Status: {'Online' if device['Online'] else 'Offline'}\n")
        results_text.insert(tk.END, f"************************\n")


def email_results(csv_output, pdf_output, csv_filename, pdf_filename, cli_mode):

    # Set up the email message
    msg = MIMEMultipart()
    config.read('config.ini')
    msg['From'] = config['EMAIL']['sender_email']
    msg['To'] = config['EMAIL']['recipient_email']
    msg['Subject'] = config['EMAIL']['subject']
    body = config['EMAIL']['body']
    recipient = config['EMAIL']['recipient_email']
    sender = config['EMAIL']['sender_email']
    smtp_server = config['SMTP']['smtp_server']
    smtp_port = int(config['SMTP']['smtp_port'])
    smtp_username = config['SMTP']['smtp_username']
    if load_decrypted_data('arg', 'smtp_password'):
        smtp_password = load_decrypted_data('arg', 'smtp_password')
    if not load_decrypted_data('arg', 'smtp_password'):
        smtp_password = config['SMTP']['smtp_password']
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

    # Add the body text to the email
    msg.attach(MIMEText(body, 'plain'))
    # Send the email
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_default_certs(ssl.Purpose.SERVER_AUTH)

    try:
        if use_ssl:
            with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:

                server.ehlo()
                server.login(smtp_username, smtp_password)
                server.send_message(msg)
        elif use_starttls:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(smtp_username, smtp_password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.ehlo()
                server.login(smtp_username, smtp_password)
                server.send_message(msg)
        if cli_mode:
            print("MAIL", f"Email from {sender} sent successfully to {recipient}")
        else:
            messagebox.showinfo("MAIL", f"Email from {sender} sent successfully to {recipient}")

    except smtplib.SMTPException as e:
        # Handle any SMTP exceptions
        print(f"An error occurred while sending the email: {str(e)}")


def teams_results(found_devices, search_values, output_mode):
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

    for device in found_devices:
        if output_mode == "agents":
            device_name, device_company, device_domain, device_os, device_win_version,\
                device_type, device_ip, device_wan_ip, device_status, device_currentuser,\
                device_lastreboot, device_serial, device_windows_serial, device_processor,\
                device_ram, device_vendor, device_model, device_gpu, \
                device_os_build, device_online, c_drive_free_gb, c_drive_used_gb,\
                c_drive_total_gb, c_drive_usage_percent = extract_device_information(device, output_mode)

            device_container = {
                "type": "Container",
                "items": [
                    {"type": "TextBlock", "text": f"Device Name: {device_name}"},
                    {"type": "TextBlock", "text": f"Company: {device_company}"},
                    {"type": "TextBlock", "text": f"Domain: {device_domain}"},
                    {"type": "TextBlock", "text": f"OS: {device_os}"},
                    {"type": "TextBlock", "text": f"Windows Version: {device_win_version}"},
                    {"type": "TextBlock", "text": f"Type: {device_type}"},
                    {"type": "TextBlock", "text": f"IP: {device_ip}"},
                    {"type": "TextBlock", "text": f"WAN IP: {device_wan_ip}"},
                    {"type": "TextBlock", "text": f"Status: {'Online' if device_status else 'Offline'}"},
                    {"type": "TextBlock", "text": f"Current User: {device_currentuser}"},
                    {"type": "TextBlock", "text": f"Last Reboot: {device_lastreboot}"},
                    {"type": "TextBlock", "text": f"Serial Number: {device_serial}"},
                    {"type": "TextBlock", "text": f"Windows License: {device_windows_serial}"},
                    {"type": "TextBlock", "text": f"Processor: {device_processor}"},
                    {"type": "TextBlock", "text": f"RAM (MB): {device_ram}"},
                    {"type": "TextBlock", "text": f"Vendor: {device_vendor}"},
                    {"type": "TextBlock", "text": f"Model: {device_model}"},
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
            snmp_device_name, device_id, device_company, device_hostname, device_online, device_type, device_security, = extract_device_information(
                device, output_mode)

            device_container = {
                "type": "Container",
                "items": [
                    {"type": "TextBlock", "text": f"Device Name: {snmp_device_name}"},
                    {"type": "TextBlock", "text": f"Device ID: {device_id}"},
                    {"type": "TextBlock", "text": f"Customer: {device_company}"},
                    {"type": "TextBlock", "text": f"Hostname: {device_hostname}"},
                    {"type": "TextBlock", "text": f"Online: {device_online}"},
                    {"type": "TextBlock", "text": f"Device Type: {device_type}"},
                    {"type": "TextBlock", "text": f"Device Security: {device_security}"},
                ]
            }
        if output_mode == "http":
            device_name, device_id, device_company, device_url, device_online, device_pattern, device_patternup = extract_device_information(
                device, output_mode)

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


def csv_results(found_devices, csv_filename, cli_mode, eolreport, output_mode):
    csv_rows = []
    for device in found_devices:
        if output_mode == "agents":

            device_name, device_company, device_domain, device_os, device_win_version,\
                device_type, device_ip, device_wan_ip, device_status, device_currentuser,\
                device_lastreboot, device_serial, device_windows_serial, device_processor,\
                device_ram, device_vendor, device_model, device_gpu,\
                device_os_build, device_online, c_drive_free_gb,\
                c_drive_used_gb, c_drive_total_gb, c_drive_usage_percent = extract_device_information(device, output_mode)

        if output_mode == "snmp":
            snmp_device_name, device_id, device_company, device_hostname, device_online, device_type, device_security, = extract_device_information(device, output_mode)

        if output_mode == "http":
            device_name, device_id, device_company, device_url, device_online, device_pattern, device_patternup = extract_device_information(device, output_mode)
        if output_mode == "tcp":
            device_name, device_id, device_company, device_online, tcp_port = extract_device_information(device, output_mode)

        if eolreport:
            eol_response = make_endoflife_request(endoflife_windows_endpoint, params=None)
            eol_response1 = make_endoflife_request(endoflife_windows_server_endpoint, params=None)
            eol_response3 = make_endoflife_request(endoflife_macos_endpoint, params=None)
            chosen_eol_date = None

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

                if chosen_eol_date:
                    # Add device information to the CSV rows with EOL date
                    csv_rows.append([device_name, device_company, device_domain,
                                     device_os, device_win_version, device_type,
                                     device_ip, device_wan_ip, device_status, device_currentuser,
                                     device_lastreboot, device_serial, device_windows_serial,
                                     device_processor, device_ram, device_vendor, device_model, device_gpu,
                                     c_drive_free_gb, c_drive_used_gb, c_drive_total_gb, c_drive_usage_percent,
                                     chosen_eol_date])

            elif 'Server' in device_os:

                if eol_response1 is not None and isinstance(eol_response1, list):
                    for item in eol_response1:
                        api_windows_srv_version = item["cycle"]
                        api_srv_eol_date = item["eol"]

                        if api_windows_srv_version in device_os:
                            chosen_eol_date = api_srv_eol_date
                            break

                if chosen_eol_date:
                    # Add device information to the CSV rows with EOL date
                    csv_rows.append([device_name, device_company, device_domain,
                                     device_os, device_win_version, device_type,
                                     device_ip, device_wan_ip, device_status, device_currentuser,
                                     device_lastreboot, device_serial, device_windows_serial,
                                     device_processor, device_ram, device_vendor, device_model, device_gpu,
                                     c_drive_free_gb, c_drive_used_gb, c_drive_total_gb, c_drive_usage_percent,
                                     chosen_eol_date])

            elif 'macOS' in device_os:
                if eol_response3 is not None and isinstance(eol_response3, list):
                    chosen_eol_date3 = None
                    for item in eol_response3:
                        api_codename = item["codename"]
                        api_mac_eol_date = item["eol"]
                        if api_codename in device_os:
                            if api_mac_eol_date:
                                chosen_eol_date = "deprecated"
                            else:
                                chosen_eol_date = "still supported"

                            break
                if chosen_eol_date:
                    # Add device information to the CSV rows with EOL date
                    csv_rows.append([device_name, device_company, device_domain,
                                     device_os, device_win_version, device_type,
                                     device_ip, device_wan_ip, device_status, device_currentuser,
                                     device_lastreboot, device_serial, device_windows_serial,
                                     device_processor, device_ram, device_vendor, device_model, device_gpu, c_drive_free_gb,
                                     c_drive_used_gb, c_drive_total_gb, c_drive_usage_percent,
                                     chosen_eol_date])

            else:
                # Add device information to the CSV rows without EOL date
                csv_rows.append([device_name, device_company, device_domain,
                                 device_os, device_win_version, device_type,
                                 device_ip, device_wan_ip, device_status, device_currentuser,
                                 device_lastreboot, device_serial, device_windows_serial,
                                 device_processor, device_ram, device_vendor, device_model, device_gpu, c_drive_free_gb, c_drive_used_gb, c_drive_total_gb, c_drive_usage_percent])

        if output_mode == "agents" and not eolreport:
            # Add device information to the CSV rows without EOL date
            csv_rows.append([device_name, device_company, device_domain,
                             device_os, device_win_version, device_type,
                             device_ip, device_wan_ip, device_status, device_currentuser,
                             device_lastreboot, device_serial, device_windows_serial,
                             device_processor, device_ram, device_vendor, device_model,
                             device_gpu, c_drive_free_gb, c_drive_used_gb, c_drive_total_gb, c_drive_usage_percent])

        if output_mode == "snmp":
            csv_rows.append([snmp_device_name, device_id, device_company,
                             device_hostname, device_online, device_type, device_security])
        if output_mode == "http":
            csv_rows.append([device_name, device_id, device_company, device_url,
                             device_online, device_pattern, device_patternup])
        if output_mode == "tcp":
            csv_rows.append([device_name, device_id, device_company, device_online, tcp_port])

    # Save the device information to a CSV file
    if output_mode == "agents":
        with open(csv_filename, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(["Device Name", "Company", "Domain", "OS",
                                 "Windows Version", "Type", "IP", "WAN IP",
                                 "Status", "Current User", "Last Reboot",
                                 "Serial Number", "Windows License",
                                 "Processor", "RAM (MB)", "Vendor",
                                 "Model", "GPU", "C: Free Space", "C: Used Space", "C: Total Space", "C: Usage Percentage", "Operating System End of Life"])
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

    if cli_mode:
        print("Search Results", f"{len(found_devices)} device(s) found. "
                                f"Device information has been saved to '{csv_filename}'.")
    else:
        messagebox.showinfo("Search Results", f"{len(found_devices)} device(s) found. "
                                              f"Device information has been saved to '{csv_filename}'.")


def pdf_results(found_devices, pdf_filename, cli_mode, output_mode):
    c = canvas.Canvas(pdf_filename, pagesize=letter)
    # Set the font and font size for the PDF
    c.setFont("Helvetica", 12)
    y = c._pagesize[1] - 50
    # Iterate through the found devices and add the contents to the PDF
    for device in found_devices:
        if output_mode == "agents":

            device_name, device_company, device_domain, device_os, device_win_version,\
                device_type, device_ip, device_wan_ip, device_status, device_currentuser,\
                device_lastreboot, device_serial, device_windows_serial, device_processor,\
                device_ram, device_vendor, device_model, device_gpu,\
                device_os_build, device_online, c_drive_free_gb,\
                c_drive_used_gb, c_drive_total_gb, c_drive_usage_percent = extract_device_information(device, output_mode)

        if output_mode == "snmp":
            snmp_device_name, device_id, device_company, device_hostname, device_online, device_type, device_security, = extract_device_information(device, output_mode)

        if output_mode == "http":
            device_name, device_id, device_company, device_url, device_online, device_pattern, device_patternup = extract_device_information(device, output_mode)
        if output_mode == "tcp":
            device_name, device_id, device_company, device_online, tcp_port = extract_device_information(device, output_mode)

        # Move to the next page if the content exceeds the page height
        if y < 50:
            c.showPage()
            y = c._pagesize[1] - 50

        if device.get('MachineName'):
            c.drawString(50, y, f"Device Name: {device['MachineName']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('Name'):
            c.drawString(50, y, f"Device Name: {device['Name']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('DeviceID'):
            c.drawString(50, y, f"Device ID: {device['DeviceID']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('Hostname'):
            c.drawString(50, y, f"Hostname (IP): {device['Hostname']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('Type'):
            c.drawString(50, y, f"Type: {device['Type']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('SecurityLevel'):
            c.drawString(50, y, f"Security: {device['SecurityLevel']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('URL'):
            c.drawString(50, y, f"URL: {device['URL']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('Pattern'):
            c.drawString(50, y, f"Pattern: {device['Pattern']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('ContainsPattern'):
            c.drawString(50, y, f"Pattern Status: {device['ContainsPattern']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('URLUp'):
            c.drawString(50, y, f"Online Status: {device['URLUp']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('CustomerName'):
            c.drawString(50, y, f"Company: {device['CustomerName']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('DomainName'):
            c.drawString(50, y, f"Domain: {device['DomainName']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('OS'):
            c.drawString(50, y, f"OS: {device['OS']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('IpAddresses'):
            c.drawString(50, y, f"LAN IP: {device['IpAddresses']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('ReportedFromIP'):
            c.drawString(50, y, f"WAN IP: {device['ReportedFromIP']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('Online'):
            c.drawString(50, y, f"Online Status: {'Online' if device['Online'] else 'Offline'}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('CurrentLoggedUsers'):
            c.drawString(50, y, f"Current User: {device['CurrentLoggedUsers']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('LastRebootTime'):
            c.drawString(50, y, f"Last Reboot: {device['LastRebootTime']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('VendorSerialNumber'):
            c.drawString(50, y, f"Serial Number: {device['VendorSerialNumber']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('WindowsSerialNumber'):
            c.drawString(50, y, f"Windows Serial Number: {device['WindowsSerialNumber']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('Processor'):
            c.drawString(50, y, f"Processor: {device['Processor']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('Memory'):
            c.drawString(50, y, f"Memory: {device['Memory']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('Vendor'):
            c.drawString(50, y, f"Vendor: {device['Vendor']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('VendorBrandModel'):
            c.drawString(50, y, f"Model: {device['VendorBrandModel']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if device.get('Display'):
            c.drawString(50, y, f"GPU: {device['Display']}")
            y -= 20
            if y < 50:
                c.showPage()
                y = c._pagesize[1] - 50
        if output_mode == "tcp":
            if tcp_port:
                c.drawString(50, y, f"TCP Port: {tcp_port}")
                y -= 20

            if device_online:
                c.drawString(50, y, f"Online Status: {'Online' if device_online else 'Offline'}")
                y -= 20

        if output_mode == "agents":
            if c_drive_free_gb:
                c.drawString(50, y, f"C: Free Disk Space: {c_drive_free_gb:.2f} GB")
                y -= 20
            if c_drive_used_gb:
                c.drawString(50, y, f"C: Used Disk Space: {c_drive_used_gb:.2f} GB")
                y -= 20
            if c_drive_total_gb:
                c.drawString(50, y, f"C: Free Disk Space: {c_drive_total_gb:.2f} GB")
                y -= 20
            if c_drive_usage_percent:
                c.drawString(50, y, f"C: Free Disk Space: {c_drive_usage_percent:.2f} %")
                y -= 20


        c.drawString(50, y, "************************")
        y -= 30
    # Save and close the PDF file
    c.save()
    if cli_mode:
        print(f"'{pdf_filename}' generated successfully!")
    else:
        messagebox.showinfo("PDF Generation", f"'{pdf_filename}' generated successfully!")


def fetch_device_information(search_options, search_values, teams_output,
                             csv_output, email_output, pdf_output, online_only, eolreport, cli_mode, output_mode, endpoint):

    try:
        page = 1
        found_devices = []
        progress_bar = tqdm(desc="Fetching devices", unit="page", leave=False)
        # Process all pages of devices
        while True:
            params = {"page": page, "itemsInPage": 50}
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
                                snmp_device_name.strip().lower() in device['Name'].lower() for snmp_device_name
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
                            in
                            value.lower().split(','))):
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
                    if output_mode == "agents" or output_mode == "snmp" :
                        if online_only and not device['Online']:
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
                           email_output, eolreport, search_values, output_mode)

    except Exception as e:
        if cli_mode:
            print("Error", str(e))
        else:
            messagebox.showerror("Error", str(e))


# Function to handle the search button click event


def output_results(found_devices, cli_mode,
                   teams_output, csv_output, pdf_output, email_output, eolreport, search_values, output_mode):
    if csv_output or pdf_output:
        current_datetime = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        subfolder_name = config['GENERAL']['filepath']
        if not os.path.exists(subfolder_name):
            os.makedirs(subfolder_name)
        csv_filename = os.path.join(subfolder_name, f"Device_{output_mode}_report_{current_datetime}.csv")
        pdf_filename = os.path.join(subfolder_name, f"Device_{output_mode}_report_{current_datetime}.pdf")


    if teams_output:
        teams_results(found_devices, search_values, output_mode)
    if csv_output:
        csv_results(found_devices, csv_filename, cli_mode, eolreport, output_mode)
    if pdf_output:
        pdf_results(found_devices, pdf_filename, cli_mode, output_mode)
    if email_output:
        email_results(csv_output, pdf_output, csv_filename, pdf_filename, cli_mode)
    # Display the results in a new window
    if not cli_mode:
        display_results(found_devices, output_mode)


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
    loading_window = tk.Toplevel()
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
    loading_label = tk.Label(loading_window, font=("arial", 40))
    loading_label.grid()
    loading_label.place(relx=0.5, rely=0.2, anchor="center")
    animate_loading(loading_label)
    search_options = str(search_options).strip('[]')
    search_values = str(search_values).strip('[]')
    loading_text_label = tk.Label(loading_window, font=("Arial", 15), text=f"Searching for..")
    loading_text_label.grid(pady=5, padx=5, sticky="nswe")
    loading_text_label.place(relx=0.5, rely=0.4, anchor="center")
    loading_text_label1 = tk.Label(loading_window, font=("Arial", 15), text=f"Search Options:{search_options}")
    loading_text_label1.grid(pady=5, padx=5, sticky="nswe")
    loading_text_label1.place(relx=0.5, rely=0.6, anchor="center")
    loading_text_label2 = tk.Label(loading_window, font=("Arial", 15), text=f"Search values:{search_values}")
    loading_text_label2.grid(pady=5, padx=5, sticky="nswe")
    loading_text_label2.place(relx=0.5, rely=0.8, anchor="center")

    return loading_window


def search_button_clicked(event=None):
    # Get the selected search options and value

    search_options = []
    search_values = []
    online_only = online_only_var.get()
    eolreport = eol_var.get()

    for i, var in enumerate(option_vars):
        option = var.get()
        value = value_entries[i].get()

        if option != "None" and value.strip() != "":
            search_options.append(option)
            search_values.append(value)

    loading_window = show_loading_window(search_options, search_values)
    # Check if any search options were selected
    if not search_options:
        loading_window.destroy()
        messagebox.showwarning("Warning", "Please Enter a value for at least one search option.")
        return

    # Fetch device information based on the selected options
    fetch_device_information(search_options, search_values, teams_output_var.get(), csv_output_var.get(),
                             email_output_var.get(), pdf_output_var.get(),
                             online_only, eolreport, cli_mode=False, output_mode="agents", endpoint=devices_endpoint)
    loading_window.destroy()


# CLI Interface Logic
if arguments.cli:

    if arguments.configure:

        if arguments.apikey:
            keyring.set_password("arg", "api_key", arguments.apikey)
            print("Successfully saved API Key")

        if arguments.teamswebhook:
            keyring.set_password("arg", "teams_webhook", arguments.teamswebhook)
            print("Successfully saved MS Teams Webhook")

        if arguments.password:
            keyring.set_password("arg", "smtp_password", arguments.password)
            print("Successfully saved SMTP Password")

        if arguments.filepath:
            config['GENERAL'] = {
                'filepath': arguments.filepath,
            }
            with open('config.ini', 'w') as configfile:
                config.write(configfile)
                print("Successfully saved filepath")

        if arguments.port:
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

        if arguments.ssl:
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
        if arguments.sender:
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
        if arguments.recipient:
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

    if arguments.agents:
        pdf_output = arguments.pdf
        csv_output = arguments.csv
        email_output = arguments.email
        teams_output = arguments.teams
        online_only = arguments.onlineonly
        eolreport = arguments.eol
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
                                 email_output=email_output, pdf_output=pdf_output, online_only=online_only,
                                 eolreport=eolreport, cli_mode=True, output_mode="agents", endpoint=devices_endpoint)

    if arguments.snmp:
        pdf_output = arguments.pdf
        csv_output = arguments.csv
        teams_output = arguments.teams
        email_output = arguments.email
        online_only = arguments.onlineonly
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
                                 email_output=email_output, pdf_output=pdf_output,
                                 online_only=online_only, eolreport=False, cli_mode=True,
                                 output_mode="snmp", endpoint=snmp_devices_endpoint)

    if arguments.http:
        pdf_output = arguments.pdf
        csv_output = arguments.csv
        teams_output = arguments.teams
        email_output = arguments.email
        online_only = arguments.onlineonly
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
                                 email_output=email_output, pdf_output=pdf_output,
                                 online_only=online_only, eolreport=False, cli_mode=True,
                                 output_mode="http", endpoint=http_devices_endpoint)

    if arguments.tcp:
        pdf_output = arguments.pdf
        csv_output = arguments.csv
        teams_output = arguments.teams
        email_output = arguments.email
        online_only = arguments.onlineonly
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
                                 email_output=email_output, pdf_output=pdf_output,
                                 online_only=online_only, eolreport=False, cli_mode=True,
                                 output_mode="tcp", endpoint=tcp_devices_endpoint)

# Tkinter Graphical Interface
else:
    sys.stdin and sys.stdin.isatty()
    window = tk.Tk()
    window.iconbitmap(icon_img)
    window.title("Atera Report Generator 1.5.3.8 - Aurora Borealis")
    images_folder = "images"
    image_path = logo_img
    image = Image.open(image_path)
    image = image.resize((600, 250), Image.LANCZOS)
    # Create an ImageTk object to display the image in the GUI
    photo = ImageTk.PhotoImage(image)

    # Create a label to display the image
    image_label = tk.Label(window, image=photo)
    image_label.grid(row=1, column=1, columnspan=2, sticky="n")
    options_frame = tk.LabelFrame(window, text="Search Options")
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
        option_label = tk.Label(options_frame, text=option)
        option_label.grid(row=i, column=0, padx=5, pady=5, sticky="w")

        value_entry = tk.Entry(options_frame)
        value_entry.grid(row=i, column=1, padx=5, pady=5)

        option_vars.append(option_var)
        value_entries.append(value_entry)
    # Create a frame for the Configuration
    configuration_frame = tk.LabelFrame(window, text="Configuration")
    configuration_frame.grid(row=3, column=2, sticky="n", padx=10, pady=10)

    bonus_frame = tk.LabelFrame(window, text="")
    bonus_frame.grid(row=2, column=2, sticky="n", padx=10, pady=10)

    # Create a frame for the Information
    information_frame = tk.LabelFrame(bonus_frame, text="Note")
    information_frame.grid(row=1, column=1, columnspan=2, padx=10, pady=10)
    OStypeinfo = tk.Label(information_frame, text="Supported OS Types: Server, Work Station, Domain Controller")
    OStypeinfo.grid()
    modules_frame = tk.LabelFrame(bonus_frame, text="Modules")
    modules_frame.grid(row=2, column=1, columnspan=2, padx=10, pady=10)
    bottom_frame = tk.LabelFrame(window, text="Informations")
    bottom_frame.grid(row=3, column=1, columnspan=2, sticky="s")
    bottom_frame1 = tk.LabelFrame(bottom_frame, width=50, height=50,)
    bottom_frame1.grid(row=1, column=1, sticky="w")


    def callback():
        webbrowser.open_new_tab("https://github.com/infovirtuel/Atera-Report-Generator")


    github_image = Image.open(github_img)

    resize_github = github_image.resize((30, 30), Image.LANCZOS)
    photoImg = ImageTk.PhotoImage(resize_github)
    github_button = tk.Button(bottom_frame1, command=callback, width=50, height=50, relief=tk.FLAT, bd=0,)
    github_button.grid()
    github_button.config(image=photoImg, compound=tk.CENTER)
    github_button.place(relx=0.5, rely=0.5, anchor='center')
    bottom_frame2 = tk.LabelFrame(bottom_frame, text="")
    bottom_frame2.grid(row=1, column=2, sticky="e")
    bottom_label1 = tk.Label(bottom_frame2, text="This software is open-source and free."
                                                 "\n If you have paid for this software, you've been scammed",
                             font=('Helveticabold', 10), fg="blue")
    bottom_label1.grid()
    version_frame = tk.LabelFrame(bottom_frame, text="")
    version_frame.grid(row=3, column=1, columnspan=2)
    version_label = tk.Label(version_frame, text="ARG V1.5.3.8 - New Feature(s) : TCP/HTTP Report & Disk Space in reports ",
                             font=('Helveticabold', 10), fg="blue")
    version_label.grid()

    # Create a frame for the Output
    output_frame = tk.LabelFrame(window, text="Output")
    output_frame.grid(row=2, column=2, sticky="s", padx=10, pady=10)
    # Online Only Checkbox
    online_only_var = tk.IntVar()
    online_only_checkbox = tk.Checkbutton(options_frame, text="Output Online Devices", variable=online_only_var)
    online_only_checkbox.grid(columnspan=2, padx=5, pady=5)
    eol_var = tk.IntVar()
    eol_checkbox = tk.Checkbutton(options_frame, text="Check device OS end of life Status", variable=eol_var)
    eol_checkbox.grid(columnspan=2, padx=5)
    eol_label = tk.Label(options_frame, text="Function provided by the endoflife.date API")
    eol_label.grid(columnspan=2, padx=5)

    # Create a checkbox for Teams output
    teams_output_var = tk.BooleanVar(value=False)
    teams_output_checkbutton = tk.Checkbutton(output_frame, text="Output to Teams", variable=teams_output_var)
    teams_output_checkbutton.grid(padx=5, pady=5)
    # Create a checkbox for CSV output
    csv_output_var = tk.BooleanVar(value=False)
    csv_output_checkbutton = tk.Checkbutton(output_frame, text="Output to CSV", variable=csv_output_var)
    csv_output_checkbutton.grid(padx=5, pady=5)
    pdf_output_var = tk.BooleanVar(value=False)
    pdf_output_checkbutton = tk.Checkbutton(output_frame, text="Output to PDF", variable=pdf_output_var)
    pdf_output_checkbutton.grid(padx=5, pady=5)
    email_output_var = tk.BooleanVar(value=False)
    email_output_checkbutton = tk.Checkbutton(output_frame, text="Send Files by email", variable=email_output_var)
    email_output_checkbutton.grid(padx=5, pady=5)


    def open_configuration_window():

        config.read('config.ini')
        config_window = tk.Toplevel(window)
        config_window.iconbitmap(icon_img)
        config_window.title("Configuration")
        configuration_frame1 = tk.LabelFrame(config_window, text="")
        configuration_frame1.grid(sticky="n", padx=10, pady=10)

        def save_config(event=None):

            def save_general_config():
                save_api_key = api_key_entry.get()
                save_teams_webhook = webhook_entry.get()
                save_subfolder_name = filepath_entry.get()
                # Store encrypted api key and webhook URL in keyring
                keyring.set_password("arg", "api_key", save_api_key)
                keyring.set_password("arg", "teams_webhook", save_teams_webhook)

                config['GENERAL'] = {
                    'filepath': save_subfolder_name,

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
            config_window.destroy()
            messagebox.showinfo("Configuration", "Configuration Saved!")

        # config_window.bind("<Return>", save_config)

        general_config_frame = tk.LabelFrame(configuration_frame1, text="General Configuration")
        general_config_frame.grid(padx=10, pady=10, row=1, column=1, sticky="n")

        # API KEY GUI ENTRY

        api_key_frame = tk.LabelFrame(general_config_frame, text="API Key (Required)")
        api_key_frame.grid(padx=10, pady=10)
        api_key_entry = tk.Entry(api_key_frame, width=50)
        api_key_entry.grid(padx=10, pady=10)
        api_key_entry.bind("<Return>", save_config)
        api_key = load_decrypted_data('arg', 'api_key')
        if api_key is not None:
            api_key_entry.insert(0, api_key)
        else:
            api_key_entry.insert(0, "Empty")  # Set a default value or empty string

        # WEBHOOK GUI ENTRY
        webhook_frame = tk.LabelFrame(general_config_frame, text="Teams Webhook URL (Optional)")
        webhook_frame.grid(padx=10, pady=47)
        webhook_entry = tk.Entry(webhook_frame, width=50)
        webhook_entry.grid(padx=10, pady=10)
        webhook_entry.bind("<Return>", save_config)
        teams_webhook = load_decrypted_data('arg', 'teams_webhook')
        if teams_webhook is not None:
            webhook_entry.insert(0, teams_webhook)
        else:
            webhook_entry.insert(0, "Empty")  # Set a default value or empty string

        # FILE PATH GUI ENTRY
        filepath_frame = tk.LabelFrame(general_config_frame, text="File Export Path (Required)")
        filepath_frame.grid(padx=10, pady=47)
        filepath_entry = tk.Entry(filepath_frame, width=50)
        filepath_entry.grid(padx=10, pady=10)
        filepath_entry.bind("<Return>", save_config)
        subfolder_name = config['GENERAL']['filepath']
        if subfolder_name is not None:
            filepath_entry.insert(0, subfolder_name)
        else:
            filepath_entry.insert(0, "Empty")  # Set a default value or empty string

        email_config_frame = tk.LabelFrame(configuration_frame1, text="Email Configuration")
        email_config_frame.grid(padx=10, pady=10, row=1, column=2)

        # EMAIL RECIPIENT GUI ENTRY
        recipient_frame = tk.LabelFrame(email_config_frame, text="Email Recipient")
        recipient_frame.grid(padx=10, pady=10)
        recipient_entry = tk.Entry(recipient_frame, width=50)
        recipient_entry.grid(padx=10, pady=10)
        recipient_entry.bind("<Return>", save_config)
        recipient = config['EMAIL']['recipient_email']
        recipient_entry.insert(0, recipient)
        # EMAIL SENDER GUI ENTRY
        sender_frame = tk.LabelFrame(email_config_frame, text="Email Sender")
        sender_frame.grid(padx=10, pady=10)
        sender_entry = tk.Entry(sender_frame, width=50)
        sender_entry.grid(padx=10, pady=10)
        sender_entry.bind("<Return>", save_config)
        sender = config['EMAIL']['sender_email']
        sender_entry.insert(0, sender)
        # EMAIL SUBJECT ENTRY
        subject_frame = tk.LabelFrame(email_config_frame, text="Email Subject")
        subject_frame.grid(padx=10, pady=10)
        subject_entry = tk.Entry(subject_frame, width=50)
        subject_entry.grid(padx=10, pady=10)
        subject_entry.bind("<Return>", save_config)
        subject = config['EMAIL']['subject']
        subject_entry.insert(0, subject)
        # EMAIL BODY ENTRY
        body_frame = tk.LabelFrame(email_config_frame, text="Email Body")
        body_frame.grid(padx=10, pady=10)
        body_entry = tk.Text(body_frame, width=50, height=10)
        body_entry.grid(padx=10, pady=10)
        body = config['EMAIL']['body']
        body_entry.insert("1.0", body)

        smtp_config_frame = tk.LabelFrame(configuration_frame1, text="SMTP Configuration")
        smtp_config_frame.grid(padx=10, pady=10, row=1, column=3)

        # SMTP SERVER ENTRY
        smtp_server_frame = tk.LabelFrame(smtp_config_frame, text="SMTP Server")
        smtp_server_frame.grid(padx=10, pady=17)
        smtp_server_entry = tk.Entry(smtp_server_frame, width=50)
        smtp_server_entry.grid(padx=10, pady=10)
        smtp_server_entry.bind("<Return>", save_config)
        smtp_server = config['SMTP']['smtp_server']
        smtp_server_entry.insert(0, smtp_server)
        # SMTP PORT ENTRY
        smtp_port_frame = tk.LabelFrame(smtp_config_frame, text="SMTP Port")
        smtp_port_frame.grid(padx=10, pady=17)
        smtp_port_entry = tk.Entry(smtp_port_frame, width=50)
        smtp_port_entry.grid(padx=10, pady=10)
        smtp_port_entry.bind("<Return>", save_config)
        smtp_port = config['SMTP']['smtp_port']
        smtp_port_entry.insert(0, smtp_port)

        smtp_encryption_frame = tk.LabelFrame(smtp_config_frame, text="SMTP Encryption")
        smtp_encryption_frame.grid(padx=10, pady=17)
        starttls_var = tk.BooleanVar(value=config['SMTP'].getboolean('starttls', False))
        starttls_checkbox = tk.Checkbutton(smtp_encryption_frame, text="StartTLS", variable=starttls_var)
        starttls_checkbox.grid(row=1, column=1, padx=10)
        ssl_var = tk.BooleanVar(value=config['SMTP'].getboolean('ssl', False))
        ssl_checkbox = tk.Checkbutton(smtp_encryption_frame, text="SSL", variable=ssl_var)
        ssl_checkbox.grid(row=1, column=2, padx=10)

        # SMTP username ENTRY
        smtp_username_frame = tk.LabelFrame(smtp_config_frame, text="SMTP Username")
        smtp_username_frame.grid(padx=10, pady=17)
        smtp_username_entry = tk.Entry(smtp_username_frame, width=50)
        smtp_username_entry.grid(padx=10, pady=10)
        smtp_username_entry.bind("<Return>", save_config)
        smtp_username = config['SMTP']['smtp_username']
        smtp_username_entry.insert(0, smtp_username)
        # SMTP Password ENTRY
        smtp_password_frame = tk.LabelFrame(smtp_config_frame, text="SMTP Password")
        smtp_password_frame.grid(padx=10, pady=17)
        smtp_password_entry = tk.Entry(smtp_password_frame, width=50)
        smtp_password_entry.grid(padx=10, pady=10)
        smtp_password_entry.bind("<Return>", save_config)
        smtp_password = load_decrypted_data('arg', 'smtp_password')
        if smtp_password is not None:
            smtp_password_entry.insert(0, smtp_password)
        else:
            smtp_password_entry.insert(0, "Empty")  # Set a default value or empty string

        # Frame for Save button
        save_frame = tk.LabelFrame(configuration_frame1, text="")
        save_frame.grid(padx=10, pady=10, row=2, column=1, columnspan=3)

        # Create a save config  button
        save_config_button = tk.Button(save_frame, text="Save Configuration",
                                       command=save_config, width=200, height=2, bg="green")
        save_config_button.grid(padx=10, pady=10)


    def open_snmp_window():
        config.read('config.ini')
        snmpwindow = tk.Toplevel(window)
        snmpwindow.iconbitmap(icon_img)
        snmpwindow.title("SNMP Reports")

        def snmp_search_button_click(event=None):

            search_options = []
            search_values = []
            online_only = online_only_var.get()
            eolreport = eol_var.get()

            for y, var in enumerate(snmp_option_vars):
                snmp_option = var.get()
                snmp_value = snmp_value_entries[y].get()

                if snmp_option != "None" and snmp_value.strip() != "":
                    search_options.append(snmp_option)
                    search_values.append(snmp_value)

            loading_window = show_loading_window(search_options, search_values)
            # Check if any search options were selected
            if not search_options:
                loading_window.destroy()
                messagebox.showwarning("Warning", "Please Enter a value for at least one search option.")
                return
            print(search_values)
            # Fetch device information based on the selected options
            fetch_device_information(search_options, search_values, teams_output_var_1.get(), csv_output_var_1.get(),
                                     email_output_var_1.get(), pdf_output_var_1.get(),
                                     online_only_var_1.get(), eolreport, cli_mode=False, output_mode="snmp",
                                     endpoint=snmp_devices_endpoint)
            loading_window.destroy()

        snmpwindow.bind("<Return>", snmp_search_button_click)


        # Create a frame for the search option
        snmp_search_option_frame = tk.LabelFrame(snmpwindow, text="Search Options")
        snmp_search_option_frame.grid(padx=10, pady=10)
        # Create a radio button for each search option
        num_options = len(searchops.options('SNMPSearchOptions'))
        options_per_column = min(num_options, 10)
        options_remaining = num_options

        for i, option in enumerate(searchops.options('SNMPSearchOptions')):
            snmp_option_var = tk.StringVar()
            snmp_option_var.set(searchops['SNMPSearchOptions'][option])
            snmp_option_label = tk.Label(snmp_search_option_frame, text=option)
            snmp_option_label.grid(row=i, column=0, padx=5, pady=5, sticky="w")

            snmp_value_entry = tk.Entry(snmp_search_option_frame)
            snmp_value_entry.grid(row=i, column=1, padx=5, pady=5)

            snmp_option_vars.append(snmp_option_var)
            snmp_value_entries.append(snmp_value_entry)
        # Add more radio buttons for other search options
        # Create a frame for the Information
        snmp_information_frame = tk.LabelFrame(snmpwindow, text="Informations")
        snmp_information_frame.grid(padx=10, pady=10)
        snmpdevicetypeinfo = tk.Label(snmp_information_frame, text="Device Types: Printer, Firewall, Other")
        snmpdevicetypeinfo.grid(padx=10)
        snmphostnameinfo = tk.Label(snmp_information_frame, text="Hostname: IP address or DNS name")
        snmphostnameinfo.grid(padx=10)
        snmp_output_frame = tk.LabelFrame(snmpwindow, text="Output")
        snmp_output_frame.grid(padx=10, pady=10)
        # Create a checkbox for Online Only Output
        online_only_var_1 = tk.IntVar()
        snmp_online_only_checkbox = tk.Checkbutton(snmp_output_frame,
                                                   text="Output Online Devices", variable=online_only_var_1)
        snmp_online_only_checkbox.grid()

        teams_output_var_1 = tk.BooleanVar(value=False)
        teams_output_checkbutton = tk.Checkbutton(snmp_output_frame,
                                                       text="Output to Teams", variable=teams_output_var_1)
        teams_output_checkbutton.grid(padx=10, pady=10)

        csv_output_var_1 = tk.BooleanVar(value=False)
        snmp_csv_output_checkbutton = tk.Checkbutton(snmp_output_frame, text="Output to CSV", variable=csv_output_var_1)
        snmp_csv_output_checkbutton.grid(padx=10, pady=10)

        pdf_output_var_1 = tk.BooleanVar(value=False)
        snmp_pdf_output_checkbutton = tk.Checkbutton(snmp_output_frame, text="Output to PDF", variable=pdf_output_var_1)
        snmp_pdf_output_checkbutton.grid(padx=10, pady=10)
        # Create a checkbox for Email output
        email_output_var_1 = tk.BooleanVar(value=False)
        snmp_email_output_checkbutton = tk.Checkbutton(snmp_output_frame,
                                                       text="Send Files by email", variable=email_output_var_1)
        snmp_email_output_checkbutton.grid(padx=5, pady=5)

        # Create a search button
        snmp_custom_font = font.Font(size=16)
        snmp_search_button1 = tk.Button(snmp_output_frame, text="Generate", command=snmp_search_button_click,
                                        width=10, height=2, font=snmp_custom_font, bg="green")
        snmp_search_button1.grid(padx=10, pady=10)

    def open_http_window():
        config.read('config.ini')
        snmpwindow = tk.Toplevel(window)
        snmpwindow.iconbitmap(icon_img)
        snmpwindow.title("HTTP Reports")

        def http_search_button_click(event=None):

            search_options = []
            search_values = []
            online_only = online_only_var.get()
            eolreport = eol_var.get()

            for y, var in enumerate(http_option_vars):
                http_option = var.get()
                http_value = http_value_entries[y].get()

                if http_option != "None" and http_value.strip() != "":
                    search_options.append(http_option)
                    search_values.append(http_value)

            loading_window = show_loading_window(search_options, search_values)
            # Check if any search options were selected
            if not search_options:
                loading_window.destroy()
                messagebox.showwarning("Warning", "Please Enter a value for at least one search option.")
                return
            print(search_values)
            # Fetch device information based on the selected options
            fetch_device_information(search_options, search_values, teams_output_var_2.get(), csv_output_var_2.get(),
                                     email_output_var_2.get(), pdf_output_var_2.get(),
                                     online_only_var_2.get(), eolreport, cli_mode=False, output_mode="http",
                                     endpoint=http_devices_endpoint)
            loading_window.destroy()

        snmpwindow.bind("<Return>", http_search_button_click)

        # Create a frame for the search option
        http_search_option_frame = tk.LabelFrame(snmpwindow, text="Search Options")
        http_search_option_frame.grid(padx=10, pady=10)
        # Create a radio button for each search option
        num_options = len(searchops.options('HTTPSearchOptions'))
        options_per_column = min(num_options, 10)
        options_remaining = num_options

        for i, option in enumerate(searchops.options('HTTPSearchOptions')):
            http_option_var = tk.StringVar()
            http_option_var.set(searchops['HTTPSearchOptions'][option])
            http_option_label = tk.Label(http_search_option_frame, text=option)
            http_option_label.grid(row=i, column=0, padx=5, pady=5, sticky="w")

            http_value_entry = tk.Entry(http_search_option_frame)
            http_value_entry.grid(row=i, column=1, padx=5, pady=5)

            http_option_vars.append(http_option_var)
            http_value_entries.append(http_value_entry)
        # Add more radio buttons for other search options
        # Create a frame for the Information
        http_output_frame = tk.LabelFrame(snmpwindow, text="Output")
        http_output_frame.grid(padx=10, pady=10)
        # Create a checkbox for Online Only Output
        online_only_var_2 = tk.IntVar()
        snmp_online_only_checkbox = tk.Checkbutton(http_output_frame,
                                                   text="Output Online Devices", variable=online_only_var_2)
        snmp_online_only_checkbox.grid()

        teams_output_var_2 = tk.BooleanVar(value=False)
        teams_output_checkbutton = tk.Checkbutton(http_output_frame,
                                                       text="Output to Teams", variable=teams_output_var_2)
        teams_output_checkbutton.grid(padx=10, pady=10)

        csv_output_var_2 = tk.BooleanVar(value=False)
        snmp_csv_output_checkbutton = tk.Checkbutton(http_output_frame, text="Output to CSV", variable=csv_output_var_2)
        snmp_csv_output_checkbutton.grid(padx=10, pady=10)

        pdf_output_var_2 = tk.BooleanVar(value=False)
        snmp_pdf_output_checkbutton = tk.Checkbutton(http_output_frame, text="Output to PDF", variable=pdf_output_var_2)
        snmp_pdf_output_checkbutton.grid(padx=10, pady=10)
        # Create a checkbox for Email output
        email_output_var_2 = tk.BooleanVar(value=False)
        snmp_email_output_checkbutton = tk.Checkbutton(http_output_frame,
                                                       text="Send Files by email", variable=email_output_var_2)
        snmp_email_output_checkbutton.grid(padx=5, pady=5)

        # Create a search button
        snmp_custom_font = font.Font(size=16)
        snmp_search_button1 = tk.Button(http_output_frame, text="Generate", command=http_search_button_click,
                                        width=10, height=2, font=snmp_custom_font, bg="green")
        snmp_search_button1.grid(padx=10, pady=10)

    def open_tcp_window():
        config.read('config.ini')
        snmpwindow = tk.Toplevel(window)
        snmpwindow.iconbitmap(icon_img)
        snmpwindow.title("TCP Reports")

        def tcp_search_button_click(event=None):

            search_options = []
            search_values = []
            online_only = online_only_var_3.get()
            eolreport = eol_var.get()

            for y, var in enumerate(tcp_option_vars):
                tcp_option = var.get()
                tcp_value = tcp_value_entries[y].get()

                if tcp_option != "None" and tcp_value.strip() != "":
                    search_options.append(tcp_option)
                    search_values.append(tcp_value)

            loading_window = show_loading_window(search_options, search_values)
            # Check if any search options were selected
            if not search_options:
                loading_window.destroy()
                messagebox.showwarning("Warning", "Please Enter a value for at least one search option.")
                return
            print(search_values)
            # Fetch device information based on the selected options
            fetch_device_information(search_options, search_values, teams_output_var_3.get(), csv_output_var_3.get(),
                                     email_output_var_3.get(), pdf_output_var_3.get(),
                                     online_only_var_3.get(), eolreport, cli_mode=False, output_mode="tcp",
                                     endpoint=tcp_devices_endpoint)
            loading_window.destroy()

        snmpwindow.bind("<Return>", tcp_search_button_click)

        # Create a frame for the search option
        tcp_search_option_frame = tk.LabelFrame(snmpwindow, text="Search Options")
        tcp_search_option_frame.grid(padx=10, pady=10)
        # Create a radio button for each search option
        num_options = len(searchops.options('TCPSearchOptions'))
        options_per_column = min(num_options, 10)
        options_remaining = num_options

        for i, option in enumerate(searchops.options('TCPSearchOptions')):
            tcp_option_var = tk.StringVar()
            tcp_option_var.set(searchops['TCPSearchOptions'][option])
            tcp_option_label = tk.Label(tcp_search_option_frame, text=option)
            tcp_option_label.grid(row=i, column=0, padx=5, pady=5, sticky="w")

            tcp_value_entry = tk.Entry(tcp_search_option_frame)
            tcp_value_entry.grid(row=i, column=1, padx=5, pady=5)

            tcp_option_vars.append(tcp_option_var)
            tcp_value_entries.append(tcp_value_entry)
        tcp_output_frame = tk.LabelFrame(snmpwindow, text="Output")
        tcp_output_frame.grid(padx=10, pady=10)
        # Create a checkbox for Online Only Output
        online_only_var_3 = tk.IntVar()
        tcp_online_only_checkbox = tk.Checkbutton(tcp_output_frame,
                                                   text="Output Online Devices", variable=online_only_var_3)
        tcp_online_only_checkbox.grid()

        teams_output_var_3 = tk.BooleanVar(value=False)
        teams_output_checkbutton = tk.Checkbutton(tcp_output_frame,
                                                       text="Output to Teams", variable=teams_output_var_3)
        teams_output_checkbutton.grid(padx=10, pady=10)

        csv_output_var_3 = tk.BooleanVar(value=False)
        tcp_csv_output_checkbutton = tk.Checkbutton(tcp_output_frame, text="Output to CSV", variable=csv_output_var_3)
        tcp_csv_output_checkbutton.grid(padx=10, pady=10)
        pdf_output_var_3 = tk.BooleanVar(value=False)
        tcp_pdf_output_checkbutton = tk.Checkbutton(tcp_output_frame, text="Output to PDF", variable=pdf_output_var_3)
        tcp_pdf_output_checkbutton.grid(padx=10, pady=10)
        email_output_var_3 = tk.BooleanVar(value=False)
        tcp_email_output_checkbutton = tk.Checkbutton(tcp_output_frame,
                                                       text="Send Files by email", variable=email_output_var_3)
        tcp_email_output_checkbutton.grid(padx=5, pady=5)

        # Create a search button
        snmp_custom_font = font.Font(size=16)
        tcp_search_button1 = tk.Button(tcp_output_frame, text="Generate", command=tcp_search_button_click,
                                        width=10, height=2, font=snmp_custom_font, bg="green")
        tcp_search_button1.grid(padx=10, pady=10)







    config_button = tk.Button(modules_frame, command=open_configuration_window, text="Configuration")
    config_button.grid(row=2, column=3, padx=10, pady=10)
    snmp_button = tk.Button(modules_frame, command=open_snmp_window, text="SNMP Reports")
    snmp_button.grid(row=2, column=1, padx=10, pady=10)
    http_button = tk.Button(modules_frame, command=open_http_window, text="HTTP Reports")
    http_button.grid(row=2, column=2, padx=10, pady=10)
    http_button = tk.Button(modules_frame, command=open_tcp_window, text="TCP Reports")
    http_button.grid(row=3, column=1, padx=10, pady=10)

    # Create a search button
    window.bind("<Return>", search_button_clicked)
    custom_font = font.Font(size=16)
    search_button = tk.Button(output_frame, command=search_button_clicked,
                              width=231, height=50, font=custom_font, relief=tk.FLAT, bd=0)
    search_button.grid(padx=10, pady=10)
    images_folder = "images"
    searchbutton_path = generate_img
    button_image = tk.PhotoImage(file=searchbutton_path)
    resized_image = button_image.subsample(1)  # Resize the image by a factor of 2
    search_button.config(image=resized_image, compound=tk.CENTER)
    # Start the main loop
    window.mainloop()
