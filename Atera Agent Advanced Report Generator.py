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
import tkinterhtml as tkhtml

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












config = configparser.ConfigParser()
searchops = configparser.ConfigParser()
config.read('config.ini')
searchops.read('searchops.ini')

# Atera API endpoints for Device Agents
base_url = "https://app.atera.com"
devices_endpoint = "/api/v3/agents"
snmp_devices_endpoint = "/api/v3/devices/snmpdevices"

# Function to make an authenticated API request
def make_atera_request(endpoint, method="GET", params=None):
    url = base_url + endpoint
    headers = {
        "Accept": "application/json",
        "X-Api-Key": config['API']['api_key']
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
    searchops['SearchOptions']['donottouch'] = "donottouch"
    with open('searchops.ini', 'w') as configfile:
        searchops.write(configfile)
generate_search_options()


def fetch_snmp_device_information(search_options, search_values, snmp_teams_output, csv_output,pdf_output, email_output, snmp_online_only):
    try:
        page = 1
        found_devices = []
        window.update()

        # Process all pages of devices
        while True:
            params = {"page": page, "itemsInPage": 50}
            response = make_atera_request(snmp_devices_endpoint, params=params)
            devices = response["items"]

            # Process the device information
            for device in devices:
                if search_options == "1":
                    for device in devices:
                        if device["Name"] is not None and search_values.lower() in device["Name"].lower():
                            if snmp_online_only and not device["Online"]:
                                continue  # Skip offline devices if checkbox is checked
                            found_devices.append(device)

                elif search_options == "2" and str(device["DeviceID"]) == search_values:
                    if snmp_online_only and not device["Online"]:
                        continue  # Skip offline devices if checkbox is checked
                    found_devices.append(device)

                elif search_options == "3":
                    for device in devices:
                        if device["CustomerName"] is not None and search_values.lower() in device["CustomerName"].lower():
                            if snmp_online_only and not device["Online"]:
                                continue  # Skip offline devices if checkbox is checked
                            found_devices.append(device)

                elif search_options == "4":
                    for device in devices:
                        if device["Hostname"] is not None and search_values.lower() in device["Hostname"].lower():
                            if snmp_online_only and not device["Online"]:
                                continue  # Skip offline devices if checkbox is checked
                            found_devices.append(device)

                elif search_options == "5":
                    for device in devices:
                        if device["Type"] is not None and search_values.lower() in device["Type"].lower():
                            if snmp_online_only and not device["Online"]:
                                continue  # Skip offline devices if checkbox is checked
                            found_devices.append(device)




                # Add more conditions for other search options

            next_page_link = response.get("nextLink")
            if next_page_link:
                page += 1
            else:
                break

        if found_devices:
            # Prepare the CSV file
            current_datetime = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            subfolder_name = config['OUTPUT_FOLDER']['filepath']
            if not os.path.exists(subfolder_name):
                os.makedirs(subfolder_name)
            csv_filename = os.path.join(subfolder_name,f"snmp_report_{current_datetime}.csv")
            csv_rows = []
            pdf_filename = os.path.join(subfolder_name,f"snmp_report_{current_datetime}.pdf")

            # Prepare the Adaptive Card
            adaptive_card = {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.3",
                "body": []
            }

            for device in found_devices:
                # Extract device information
                device_name = device["Name"]
                device_id = device["DeviceID"]
                device_customer = device["CustomerName"]
                device_hostname = device["Hostname"]
                device_online = device["Online"]
                device_type =  device["Type"]
                device_security = device["SecurityLevel"]




                # Add device information to the CSV rows
                csv_rows.append([device_name, device_id, device_customer, device_hostname, device_online, device_type, device_security, ])

                # Create an Adaptive Card for each device
                adaptive_card["body"].append(
                    {
                        "type": "Container",
                        "items": [
                            {"type": "TextBlock", "text": f"Device Name: {device_name}"},
                            {"type": "TextBlock", "text": f"Device ID: {device_id}"},
                            {"type": "TextBlock", "text": f"Customer: {device_customer}"},
                            {"type": "TextBlock", "text": f"Hostname: {device_hostname}"},
                            {"type": "TextBlock", "text": f"Online: {device_online}"},
                            {"type": "TextBlock", "text": f"Device Type: {device_type}"},
                            {"type": "TextBlock", "text": f"Device Security: {device_security}"},
                        ]
                    }
                )

            # Save the device information to a CSV file
            if csv_output:  # Check if CSV output is enabled
                with open(csv_filename, "w", newline="") as csvfile:
                    csv_writer = csv.writer(csvfile)
                    csv_writer.writerow(["Device Name", "DeviceID", "Company", "Hostname", "Online", "Type", "Security", ])
                    csv_writer.writerows(csv_rows)
            # Show a message box with the number of devices found
                messagebox.showinfo("Search Results", f"devices found. Device information has been saved to '{csv_filename}'.")

            if pdf_output:
               pdf_results(found_devices, pdf_filename)

            if email_output:
                email_results(csv_output, pdf_output, csv_filename, pdf_filename)

            # Display the results in a new window
            display_results(found_devices)


            # Convert the Adaptive Card to JSON string
            adaptive_card_json = json.dumps(adaptive_card)

            # Post the Adaptive Card to Teams
            if snmp_teams_output:
                teams_webhook = config['WEBHOOK']['teams_webhook']
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
    except Exception as e:
        messagebox.showerror("Error", str(e))
# Function to fetch device information

# Function to display the results in a new window
def display_results(found_devices):

    num_devices = len(found_devices)
    messagebox.showinfo("Devices Found", f"Number of devices found: {num_devices}")

    # Create a new window
    results_window = tk.Toplevel(window)
    results_window.iconbitmap("images/atera_icon.ico")
    results_window.title("Search Results")
    # Create a text widget to display the results
    results_text = tk.Text(results_window, height=40, width=80)
    results_text.grid()



    # Insert the results into the text widget
    for device in found_devices:
        #REGULAR DEVICES
        if device.get('MachineName'):
            results_text.insert(tk.END, f"Device Name: {device['MachineName']}\n")
        if device.get('DomainName'):
            results_text.insert(tk.END, f"Domain Name: {device['DomainName']}\n")
        if device.get('OS'):
            results_text.insert(tk.END, f"OS: {device['OS']}\n")
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
        #SNMP DEVICES
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
        #VALID FOR ALL REPORT TYPES
        if device.get('CustomerName'):
            results_text.insert(tk.END, f"Company: {device['CustomerName']}\n")
        results_text.insert(tk.END, f"Status: {'Online' if device['Online'] else 'Offline'}\n")
        results_text.insert(tk.END, f"************************\n")


def email_results(csv_output, pdf_output, csv_filename, pdf_filename):

    # Display a message indicating the PDF generation is complete
    # Set up the email message
    msg = MIMEMultipart()
    msg['From'] = config['EMAIL_SENDER']['sender_email']
    msg['To'] = config['EMAIL_RECIPIENT']['recipient_email']
    msg['Subject'] = config['EMAIL_SUBJECT']['subject']
    body = config['EMAIL_BODY']['body']
    recipient = config['EMAIL_RECIPIENT']['recipient_email']
    sender = config['EMAIL_SENDER']['sender_email']
    smtp_server = config['SMTP']['smtp_server']
    smtp_port = config['SMTP']['smtp_port']
    smtp_username = config['SMTP']['smtp_username']
    smtp_password = config['SMTP']['smtp_password']

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

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.send_message(msg)
    messagebox.showinfo("MAIL", f"Email from {sender} sent successfully to {recipient} ")




def pdf_results(found_devices,pdf_filename):
    c = canvas.Canvas(pdf_filename, pagesize=letter)

    # Set the font and font size for the PDF
    c.setFont("Helvetica", 12)
    y = c._pagesize[1] - 50
    # Iterate through the found devices and add the contents to the PDF
    for device in found_devices:
        if device.get('MachineName'):
            c.drawString(50, y, f"Device Name: {device['MachineName']}")
            y -= 20
        if device.get('Name'):
            c.drawString(50, y, f"Device Name: {device['Name']}")
            y -= 20
        if device.get('DeviceID'):
            c.drawString(50, y, f"Device ID: {device['DeviceID']}")
            y -= 20
        if device.get('Hostname'):
            c.drawString(50, y, f"Hostname (IP): {device['Hostname']}")
            y -= 20
        if device.get('Type'):
            c.drawString(50, y, f"Type: {device['Type']}")
            y -= 20
        if device.get('SecurityLevel'):
            c.drawString(50, y, f"Security: {device['SecurityLevel']}")
            y -= 20

        if device.get('CustomerName'):
            c.drawString(50, y, f"Company: {device['CustomerName']}")
            y -= 20
        if device.get('DomainName'):
            c.drawString(50, y, f"Domain: {device['DomainName']}")
            y -= 20
        if device.get('OS'):
            c.drawString(50, y, f"OS: {device['OS']}")
            y -= 20
        if device.get('IpAddresses'):
            c.drawString(50, y, f"LAN IP: {device['IpAddresses']}")
            y -= 20
        if device.get('ReportedFromIP'):
            c.drawString(50, y, f"WAN IP: {device['ReportedFromIP']}")
            y -= 20
        if device.get('Online'):
            c.drawString(50, y, f"Online Status: {'Online' if device['Online'] else 'Offline'}\n")
            y -= 30
        if device.get('CurrentLoggedUsers'):
            c.drawString(50, y, f"Current User: {device['CurrentLoggedUsers']}")
            y -= 20
        if device.get('LastRebootTime'):
            c.drawString(50, y, f"Last Reboot: {device['LastRebootTime']}")
            y -= 20
        if device.get('VendorSerialNumber'):
            c.drawString(50, y, f"Serial Number: {device['VendorSerialNumber']}")
            y -= 20
        if device.get('WindowsSerialNumber'):
            c.drawString(50, y, f"Windows Serial Number: {device['WindowsSerialNumber']}")
            y -= 20
        if device.get('Processor'):
            c.drawString(50, y, f"Processor: {device['Processor']}")
            y -= 20
        if device.get('Memory'):
            c.drawString(50, y, f"Memory: {device['Memory']}")
            y -= 20
        if device.get('Vendor'):
            c.drawString(50, y, f"Vendor: {device['Vendor']}")
            y -= 20
        if device.get('VendorBrandModel'):
            c.drawString(50, y, f"Model: {device['VendorBrandModel']}")
            y -= 20
        if device.get('Display'):
            c.drawString(50, y, f"GPU: {device['Display']}")
            y -= 20
        c.drawString(50, y, "************************")
        y -= 30
        # Move to the next page if the content exceeds the page height
        if y < 50:
            c.showPage()
            y = c._pagesize[1] - 50
    # Save and close the PDF file
    c.save()
    messagebox.showinfo("PDF Generation", f"'{pdf_filename}' generated successfully!")

def fetch_device_information(search_options, search_values, teams_output, csv_output, email_output, pdf_output,online_only):
    try:
        page = 1
        found_devices = []

        # Process all pages of devices
        while True:
            params = {"page": page, "itemsInPage": 50}
            response = make_atera_request(devices_endpoint, params=params)
            devices = response["items"]

            # Process the device information
            for device in devices:
                match = True
                window.update()
                # Check if the device matches the search options and values
                for option, value in zip(search_options, search_values):
                    if option == "Device Name" and (
                            not device['MachineName'] or value.lower() not in device['MachineName'].lower()):
                        match = False
                        break
                    elif option == "Company" and (
                            not device['CustomerName'] or value.lower() not in device['CustomerName'].lower()):
                        match = False
                        break
                    elif option == "Serial Number" and value != device['VendorSerialNumber']:
                        match = False
                        break
                    elif option == "LAN IP" and (
                            not device['IpAddresses'] or value not in device['IpAddresses']):
                        match = False
                        break
                    elif option == "OS Type" and (
                            not device['OSType'] or value.lower() not in device['OSType'].lower()):
                        match = False
                        break
                    elif option == "Vendor" and (
                            not device['Vendor'] or value.lower() not in device['Vendor'].lower()):
                        match = False
                        break
                    elif option == "WAN IP" and (
                            not device['ReportedFromIP'] or value.lower() not in device['ReportedFromIP'].lower()):
                        match = False
                        break
                    elif option == "Domain Name" and (
                            not device['DomainName'] or value.lower() not in device['DomainName'].lower()):
                        match = False
                        break
                    elif option == "Username" and (
                            not device['LastLoginUser'] or value.lower() not in device['LastLoginUser'].lower()):
                        match = False
                        break
                    elif option == "Vendor Model" and (
                            not device['VendorBrandModel'] or value.lower() not in device['VendorBrandModel'].lower()):
                        match = False
                        break
                    elif option == "Processor" and (
                            not device['Processor'] or value.lower() not in device['Processor'].lower()):
                        match = False
                        break
                    elif option == "Core Amount" and int(value) != device['ProcessorCoresCount']:
                        match = False
                        break
                    elif option == "OS VERSION" and (
                            not device['OS'] or value.lower() not in device['OS'].lower()):
                        match = False
                        break
                    elif option == "donottouch" and (
                            not device['CustomerID'] or value.lower() not in device['CustomerID'].lower()):
                        match = False
                        break


                # Add the device to the results if it matches the search criteria
                if match:
                    if online_only and not device['Online']:
                        continue
                    found_devices.append(device)

            # Break the loop if all devices have been processed
            next_page_link = response.get("nextLink")
            if next_page_link:
                page += 1
            else:
                break

        if found_devices:
            # Prepare the CSV file
            current_datetime = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            subfolder_name = config['OUTPUT_FOLDER']['filepath']
            if not os.path.exists(subfolder_name):
                os.makedirs(subfolder_name)
            csv_filename = os.path.join(subfolder_name,f"Device_report_{current_datetime}.csv")
            pdf_filename = os.path.join(subfolder_name, f"Device_report_{current_datetime}.pdf")
            csv_rows = []

            # Prepare the Adaptive Card
            adaptive_card = {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.3",
                "body": []
            }

            for device in found_devices:
                # Extract device information
                device_name = device["MachineName"]
                device_company = device["CustomerName"]
                device_domain = device["DomainName"]
                device_os = device["OS"]
                device_win_version = device["OSVersion"]
                device_type = device["OSType"]
                device_ip = device["IpAddresses"]
                device_wan_ip = device["ReportedFromIP"]
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
                device_lastlogin = device["LastLoginUser"]
                # Add device information to the CSV rows
                csv_rows.append([device_name, device_company, device_domain, device_os, device_win_version, device_type, device_ip, device_wan_ip, device_status, device_currentuser, device_lastreboot, device_serial, device_windows_serial, device_processor, device_ram, device_vendor, device_model,device_gpu, ])

                # Create an Adaptive Card for each device
                adaptive_card["body"].append(
                    {
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
                            {"type": "TextBlock", "text": f"Numéro de Série: {device_serial}"},
                            {"type": "TextBlock", "text": f"License Windows: {device_windows_serial}"},
                            {"type": "TextBlock", "text": f"Processeur: {device_processor}"},
                            {"type": "TextBlock", "text": f"RAM (MB): {device_ram}"},
                            {"type": "TextBlock", "text": f"Manufacturier: {device_vendor}"},
                            {"type": "TextBlock", "text": f"Modele: {device_model}"},
                            {"type": "TextBlock", "text": f"GPU: {device_gpu}"}


                        ]
                    }
                )

            # Save the device information to a CSV file
            if csv_output:  # Check if CSV output is enabled
                with open(csv_filename, "w", newline="") as csvfile:
                    csv_writer = csv.writer(csvfile)
                    csv_writer.writerow(["Device Name", "Company", "Domain", "OS", "Windows Version", "Type", "IP", "WAN IP", "Status", "Current User", "Last Reboot", "Numéro de Série","License Windows","Processeur","RAM (MB)","Manufacturier","Modele","GPU", ])
                    csv_writer.writerows(csv_rows)

            # Show a message box with the number of devices found
                messagebox.showinfo("Search Results", f"{len(found_devices)} device(s) found. Device information has been saved to '{csv_filename}'.")
            if pdf_output:
                pdf_results(found_devices, pdf_filename)
            if email_output:
                email_results(csv_output, pdf_output, csv_filename, pdf_filename)

            # Display the results in a new window
            display_results(found_devices)
            # Convert the Adaptive Card to JSON string
            adaptive_card_json = json.dumps(adaptive_card)
            # Post the Adaptive Card to Teams
            if teams_output:
                teams_webhook = config['WEBHOOK']['teams_webhook']
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
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Function to handle the search button click event
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

    frame_duration = 200  # Adjust the duration between frames (in milliseconds)

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
    loading_text_label.grid(pady=5, padx=5,sticky="nswe")
    loading_text_label.place(relx=0.5, rely=0.4, anchor="center")
    loading_text_label1 = tk.Label(loading_window, font=("Arial", 15), text=f"Search Options:{search_options}")
    loading_text_label1.grid(pady=5, padx=5,sticky="nswe")
    loading_text_label1.place(relx=0.5, rely=0.6, anchor="center")
    loading_text_label2 = tk.Label(loading_window, font=("Arial", 15), text=f"Search values:{search_values}")
    loading_text_label2.grid(pady=5, padx=5,sticky="nswe")
    loading_text_label2.place(relx=0.5, rely=0.8, anchor="center")

    return loading_window
def search_button_clicked(event=None):
    # Get the selected search options and value

    search_options = []
    search_values = []
    online_only = online_only_var.get()

    for i, var in enumerate(option_vars):
        option = var.get()
        value = value_entries[i].get()

        if option != "None" and value.strip() != "":
            search_options.append(option)
            search_values.append(value)

    print("Search Options:", search_options)
    print("Search Values:", search_values)
    loading_window = show_loading_window(search_options,search_values)
    # Check if any search options were selected
    if not search_options:
        messagebox.showwarning("Warning", "Please Enter a value for at least one search option.")
        return

    # Fetch device information based on the selected options
    fetch_device_information(search_options, search_values, teams_output_var.get(), csv_output_var.get(), email_output_var.get(),pdf_output_var.get(), online_only)
    loading_window.destroy()

# Create the main window
window = tk.Tk()
window.iconbitmap("images/atera_icon.ico")
window.title("Atera Agent Advanced Report")
images_folder = "images"
#image_path = os.path.join(images_folder, "Atera_logo.jpg")
image_path = "images/logo.png"
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
# Create search option variables and value entry widgets
option_vars = []
value_entries = []
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
bonus_frame.grid(row=2,column=2, sticky="n", padx=10, pady=10)

# Create a frame for the Information
information_frame = tk.LabelFrame(bonus_frame, text="Note")
information_frame.grid(row=1,column=1,columnspan=2, padx=10, pady=10)
OStypeinfo = tk.Label(information_frame, text="Supported OS Types: Server, Work Station, Domain Controller")
OStypeinfo.grid()
modules_frame = tk.LabelFrame(bonus_frame, text="Modules")
modules_frame.grid(row=2,column=1,columnspan=2, padx=10, pady=10)
bottom_frame = tk.LabelFrame(window, text="Informations")
bottom_frame.grid(row=3, column=1,columnspan=2, sticky="s")
bottom_frame1 = tk.LabelFrame(bottom_frame,width=50, height=50,)
bottom_frame1.grid(row=1, column=1, sticky="w")
def callback():
   webbrowser.open_new_tab("https://github.com/infovirtuel/Atera-Report-Generator")

github_image = Image.open("images/github.png")
resize_github = github_image.resize((30,30), Image.LANCZOS)
photoImg = ImageTk.PhotoImage(resize_github)
github_button = tk.Button(bottom_frame1, command= callback, width=50, height=50, relief=tk.FLAT, bd=0,)
github_button.grid()
github_button.config(image=photoImg, compound=tk.CENTER)
github_button.place(relx=0.5, rely=0.5, anchor='center')
bottom_frame2 = tk.LabelFrame(bottom_frame, text="")
bottom_frame2.grid(row=1, column=2, sticky="e")
bottom_label1 = tk.Label(bottom_frame2, text="This software is open-source and free.\n If you have paid for this software, you've been scammed",font=('Helveticabold', 10), fg="blue")
bottom_label1.grid()
version_frame = tk.LabelFrame(bottom_frame, text="")
version_frame.grid(row=3, column=1,columnspan=2)
version_label = tk.Label(version_frame, text="ARG V1.5 - New Feature(s) : Email Reports for SNMP and GUI email configuration",font=('Helveticabold', 10), fg="blue")
version_label.grid()
# Function to load the API key from the config file


def create_config():
    if 'API' not in config:
        # Create 'API' section in the config file
        config['API'] = {}
    if 'WEBHOOK' not in config:
        # Create 'API' section in the config file
        config['WEBHOOK'] = {}


    if 'SMTP' not in config:
        # Create 'API' section in the config file
        config['SMTP'] = {}
    if 'OUTPUT_FOLDER' not in config:
        # Create 'API' section in the config file
        config['OUTPUT_FOLDER'] = {}
    if 'EMAIL_SENDER' not in config:
        # Create 'API' section in the config file
        config['EMAIL_SENDER'] = {}
    if 'EMAIL_RECIPIENT' not in config:
        # Create 'API' section in the config file
        config['EMAIL_RECIPIENT'] = {}
    if 'EMAIL_SUBJECT' not in config:
        # Create 'API' section in the config file
        config['EMAIL_SUBJECT'] = {}
    if 'EMAIL_BODY' not in config:
        # Create 'API' section in the config file
        config['EMAIL_BODY'] = {}

    if 'api_key' not in config['API']:
        config['API']['api_key'] = "ENTER API KEY"
    if 'teams_webhook' not in config['WEBHOOK']:
        config['WEBHOOK']['teams_webhook'] = "ENTER WEBHOOK HERE"
    if 'filepath' not in config['OUTPUT_FOLDER']:
        config['OUTPUT_FOLDER']['filepath'] = "C:/ENTER/PATH/HERE"
    if 'sender_email' not in config['EMAIL_SENDER']:
        config['EMAIL_SENDER']['sender_email'] = "defaultsender@default.com"
    if 'recipient_email' not in config['EMAIL_RECIPIENT']:
        config['EMAIL_RECIPIENT']['recipient_email'] = "defaultrecipient@default.com"
    if 'subject' not in config['EMAIL_SUBJECT']:
        config['EMAIL_SUBJECT']['subject'] = "Atera Report Results"
    if 'body' not in config['EMAIL_BODY']:
        config['EMAIL_BODY']['body'] = "Please find the attached results file"
    if 'smtp_server' not in config['SMTP']:
        config['SMTP']['smtp_server'] = "smtp.office365.com"
    if 'smtp_port' not in config['SMTP']:
        config['SMTP']['smtp_port'] = "587"
    if 'smtp_username' not in config['SMTP']:
        config['SMTP']['smtp_username'] = "defaultsender@default.com"
    if 'smtp_password' not in config['SMTP']:
        config['SMTP']['smtp_password'] = "defaultpassword123"
    with open('config.ini', 'w') as configfile:
        config.write(configfile)

create_config()

def load_config():
    config.read('config.ini')
    api_key = config['API']['api_key']
    teams_webhook = config['WEBHOOK']['teams_webhook']
    subfolder_name = config['OUTPUT_FOLDER']['filepath']
    recipient_email = config['EMAIL_RECIPIENT']['recipient_email']
    sender_email = config['EMAIL_SENDER']['sender_email']
    subject = config['EMAIL_SUBJECT']['subject']
    body = config['EMAIL_BODY']['body']
load_config()



# Create a frame for the Output
output_frame = tk.LabelFrame(window, text="Output")
output_frame.grid(row=2, column=2,sticky="s", padx=10, pady=10 )
#Online Only Checkbox
online_only_var = tk.IntVar()
online_only_checkbox = tk.Checkbutton(options_frame, text="Output Online Devices", variable=online_only_var)
online_only_checkbox.grid(columnspan=2,padx=5, pady=5)
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
pdf_output_checkbutton = tk.Checkbutton(output_frame, text="Send Files by email", variable=email_output_var)
pdf_output_checkbutton.grid(padx=5, pady=5)


def open_configuration_window():
    config.read('config.ini')
    config_window = tk.Toplevel(window)
    config_window.iconbitmap("images/atera_icon.ico")
    config_window.title("Configuration")
    configuration_frame1 = tk.LabelFrame(config_window, text="")
    configuration_frame1.grid(sticky="n", padx=10, pady=10)
    def save_config(event=None):
        def save_api_key():
            api_key = api_key_entry.get()

            # Update the config file with the API key
            config['API'] = {'api_key': api_key}
            with open('config.ini', 'w') as configfile:
                config.write(configfile)
        def save_webhook():
            teams_webhook = webhook_entry.get()

            # Update the config file with the API key
            config['WEBHOOK'] = {'teams_webhook': teams_webhook}
            with open('config.ini', 'w') as configfile:
                config.write(configfile)
        def save_filepath():
            subfolder_name = filepath_entry.get()

            # Update the config file with the API key
            config['OUTPUT_FOLDER'] = {'filepath': subfolder_name}
            with open('config.ini', 'w') as configfile:
                config.write(configfile)

        def save_email_recipient():
            email_recipient = recipient_entry.get()
            # Update the config file with the API key
            config['EMAIL_RECIPIENT'] = {'recipient_email': email_recipient}
            with open('config.ini', 'w') as configfile:
                config.write(configfile)

        def save_email_sender():
            email_sender = sender_entry.get()
            # Update the config file with the API key
            config['EMAIL_SENDER'] = {'sender_email': email_sender}
            with open('config.ini', 'w') as configfile:
                config.write(configfile)

        def save_email_subject():
            email_subject = subject_entry.get()
            # Update the config file with the API key
            config['EMAIL_SUBJECT'] = {'subject': email_subject}
            with open('config.ini', 'w') as configfile:
                config.write(configfile)

        def save_email_body():
            email_body = body_entry.get("1.0", "end-1c")
            # Update the config file with the API key
            config['EMAIL_BODY'] = {'body': email_body}
            with open('config.ini', 'w') as configfile:
                config.write(configfile)




        save_filepath()
        save_webhook()
        save_api_key()
        save_email_recipient()
        save_email_sender()
        save_email_subject()
        save_email_body()


        messagebox.showinfo("Configuration", "Configuration Saved!")
        config_window.destroy()
    #config_window.bind("<Return>", save_config)


    general_config_frame = tk.LabelFrame(configuration_frame1, text="General Configuration")
    general_config_frame.grid(padx=10, pady=10, row=1, column=1)


    #API KEY GUI ENTRY
    api_key_frame = tk.LabelFrame(general_config_frame, text="Atera API Key (Required)")
    api_key_frame.grid(padx=10, pady=10)
    api_key_entry = tk.Entry(api_key_frame, width=50, )
    api_key_entry.grid(padx=10, pady=10)
    api_key = config['API']['api_key']
    api_key_entry.insert(0, api_key)
    #WEBHOOK GUI ENTRY
    webhook_frame = tk.LabelFrame(general_config_frame, text="Teams Webhook URL (Optional)")
    webhook_frame.grid(padx=10, pady=10)
    webhook_entry = tk.Entry(webhook_frame, width=50)
    webhook_entry.grid(padx=10, pady=10)
    teams_webhook = config['WEBHOOK']['teams_webhook']
    webhook_entry.insert(0, teams_webhook)
    #FILE PATH GUI ENTRY
    filepath_frame = tk.LabelFrame(general_config_frame, text="File Export Path (Required)")
    filepath_frame.grid(padx=10, pady=10)
    filepath_entry = tk.Entry(filepath_frame, width=50)
    filepath_entry.grid(padx=10, pady=10)
    subfolder_name = config['OUTPUT_FOLDER']['filepath']
    filepath_entry.insert(0, subfolder_name)

    email_config_frame = tk.LabelFrame(configuration_frame1, text="Email Configuration")
    email_config_frame.grid(padx=10, pady=10, row=1, column=2)


    #EMAIL RECIPIENT GUI ENTRY
    recipient_frame = tk.LabelFrame(email_config_frame, text="Email Recipient")
    recipient_frame.grid(padx=10, pady=10)
    # Create an entry field for Recipient
    recipient_entry = tk.Entry(recipient_frame, width=50)
    recipient_entry.grid(padx=10, pady=10)
    recipient = config['EMAIL_RECIPIENT']['recipient_email']
    recipient_entry.insert(0, recipient)
    #EMAIL SENDER GUI ENTRY
    sender_frame = tk.LabelFrame(email_config_frame, text="Email Sender")
    sender_frame.grid(padx=10, pady=10)
    # Create an entry field for Sender
    sender_entry = tk.Entry(sender_frame, width=50)
    sender_entry.grid(padx=10, pady=10)
    sender = config['EMAIL_SENDER']['sender_email']
    sender_entry.insert(0, sender)
    #EMAIL SUBJECT ENTRY
    subject_frame = tk.LabelFrame(email_config_frame, text="Email Subject")
    subject_frame.grid(padx=10, pady=10)
    # Create an entry field for Subject
    subject_entry = tk.Entry(subject_frame, width=50)
    subject_entry.grid(padx=10, pady=10)
    subject = config['EMAIL_SUBJECT']['subject']
    subject_entry.insert(0, subject)
    #EMAIL BODY ENTRY
    body_frame = tk.LabelFrame(email_config_frame, text="Email Body")
    body_frame.grid(padx=10, pady=10)
    # Create an entry field for Subject
    body_entry = tk.Text(body_frame, width=50, height=10)
    body_entry.grid(padx=10, pady=10)
    body = config['EMAIL_BODY']['body']
    body_entry.insert("1.0", body)


    save_frame = tk.LabelFrame(configuration_frame1, text="")
    save_frame.grid(padx=10, pady=10, row=2, column=1, columnspan=2)

    smtp_config_frame = tk.Label(save_frame, text="For the SMTP configuration, \n Please enter your informations in config.ini")
    smtp_config_frame.grid(padx=10, pady=10)


    # Create a save config  button
    save_config_button = tk.Button(save_frame, text="Save Configuration",command=save_config)
    save_config_button.grid(padx=10, pady=10)
def open_snmp_window():
    config.read('config.ini')
    snmpwindow = tk.Toplevel(window)
    snmpwindow.iconbitmap("images/atera_icon.ico")
    snmpwindow.title("AARG SNMP Report Tool")
    def snmp_search_button_click(event=None):
        search_options = snmp_search_option_var.get()
        search_values = snmp_search_value_entry.get().strip()
        snmp_teams_output = snmp_teams_output_var.get()
        csv_output = csv_output_var.get()
        pdf_output = pdf_output_var.get()
        email_output = email_output_var.get()
        snmp_online_only = snmp_online_only_var.get()
        loading_window = show_loading_window(search_options,search_values)
        # Save the selected option to the config file
        config['SEARCH'] = {'search_option': search_options}
        with open('config.ini', 'w') as configfile:
            config.write(configfile)

        if search_values:
            fetch_snmp_device_information(search_options, search_values, snmp_teams_output, csv_output, pdf_output, email_output, snmp_online_only)
            loading_window.destroy()
        else:
            messagebox.showwarning("Warning", "Please enter a search value.")

    snmpwindow.bind("<Return>", snmp_search_button_click)

    # Create a frame for the search value
    snmp_search_value_frame = tk.LabelFrame(snmpwindow, text="Search Value")
    snmp_search_value_frame.grid(padx=10, pady=10)
    # Create an entry field for the search value
    snmp_search_value_entry = tk.Entry(snmp_search_value_frame, width=50)
    snmp_search_value_entry.grid(padx=5, pady=5)
    snmp_search_value_entry.insert(0, "Ex. fortigate client1")
    # Create a frame for the search option
    snmp_search_option_frame = tk.LabelFrame(snmpwindow, text="Search Options")
    snmp_search_option_frame.grid(padx=10, pady=10)
    # Create a radio button for each search option
    snmp_search_option_var = tk.StringVar(value="1")
    snmp_search_option_1 = tk.Radiobutton(snmp_search_option_frame, text="Device Name", variable=snmp_search_option_var, value="1")
    snmp_search_option_1.grid()
    snmp_search_option_2 = tk.Radiobutton(snmp_search_option_frame, text="DeviceID", variable=snmp_search_option_var, value="2")
    snmp_search_option_2.grid()
    snmp_search_option_3 = tk.Radiobutton(snmp_search_option_frame, text="CustomerName", variable=snmp_search_option_var, value="3")
    snmp_search_option_3.grid()
    snmp_search_option_4 = tk.Radiobutton(snmp_search_option_frame, text="Hostname", variable=snmp_search_option_var, value="4")
    snmp_search_option_4.grid()
    snmp_search_option_5 = tk.Radiobutton(snmp_search_option_frame, text="Device Type", variable=snmp_search_option_var, value="5")
    snmp_search_option_5.grid()
    # Add more radio buttons for other search options
    # Create a frame for the Information
    snmp_information_frame = tk.LabelFrame(snmpwindow, text="Informations")
    snmp_information_frame.grid(padx=10, pady=10)
    SNMPDevicetypeinfo = tk.Label(snmp_information_frame, text="Device Types: Printer, Firewall, Other")
    SNMPDevicetypeinfo.grid(padx=10)
    SNMPhostnameinfo = tk.Label(snmp_information_frame, text="Hostname: IP address or DNS name")
    SNMPhostnameinfo.grid(padx=10)
    versioninfo = tk.Label(snmp_information_frame, text="This Module will be upgraded with: \n Advanced reports \n Prettier UI")
    versioninfo.grid(padx=10)

    snmp_output_frame = tk.LabelFrame(snmpwindow, text="Output")
    snmp_output_frame.grid(padx=10, pady=10)
    # Create a checkbox for Online Only Output
    snmp_online_only_var = tk.IntVar()
    snmp_online_only_checkbox = tk.Checkbutton(snmp_output_frame, text="Output Online Devices", variable=snmp_online_only_var)
    snmp_online_only_checkbox.grid()
    # Create a checkbox for Teams output
    snmp_teams_output_var = tk.BooleanVar(value=False)
    snmp_teams_output_checkbutton = tk.Checkbutton(snmp_output_frame, text="Output to Teams", variable=snmp_teams_output_var)
    snmp_teams_output_checkbutton.grid(padx=10, pady=10)
    # Create a checkbox for CSV output
    csv_output_var = tk.BooleanVar(value=False)
    snmp_csv_output_checkbutton = tk.Checkbutton(snmp_output_frame, text="Output to CSV", variable=csv_output_var)
    snmp_csv_output_checkbutton.grid(padx=10, pady=10)
    pdf_output_var = tk.BooleanVar(value=False)
    snmp_pdf_output_checkbutton = tk.Checkbutton(snmp_output_frame, text="Output to PDF", variable=pdf_output_var)
    snmp_pdf_output_checkbutton.grid(padx=10, pady=10)
    snmp_email_output_checkbutton = tk.Checkbutton(snmp_output_frame, text="Send Files by email", variable=email_output_var)
    snmp_email_output_checkbutton.grid(padx=5, pady=5)

    # Create a search button
    snmp_custom_font = font.Font(size=16)
    snmp_search_button1 = tk.Button(snmp_output_frame, text="Generate!", command=snmp_search_button_click, width=10, height=2, font=snmp_custom_font)
    snmp_search_button1.grid(padx=10, pady=10)
config_button = tk.Button(modules_frame, command=open_configuration_window, text="Configuration")
config_button.grid(row=2,column=3,padx=10, pady=10)
snmp_button = tk.Button(modules_frame, command=open_snmp_window, text="SNMP Reports")
snmp_button.grid(row=2,column=1,padx=10, pady=10)
# Create a search button
window.bind("<Return>", search_button_clicked)
custom_font = font.Font(size=16)
search_button = tk.Button(output_frame, command=search_button_clicked, width=231, height=50, font=custom_font, relief=tk.FLAT, bd=0 )
search_button.grid(padx=10, pady=10)
images_folder = "images"
#searchbutton_path = os.path.join(images_folder, "generate.png")
searchbutton_path = "images/generate.png"
button_image = tk.PhotoImage(file=searchbutton_path)
resized_image = button_image.subsample(1)  # Resize the image by a factor of 2
search_button.config(image=resized_image, compound=tk.CENTER)
# Start the main loop
window.mainloop()
