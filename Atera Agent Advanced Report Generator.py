import requests
import json
import csv
import tkinter as tk
import configparser
import datetime
from tkinter import messagebox
from PIL import ImageTk, Image
import os
import subprocess
from tkinter import font


config = configparser.ConfigParser()
config.read('config.ini')

# Atera API endpoints for Device Agents
base_url = "https://app.atera.com"
devices_endpoint = "/api/v3/agents"

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

# Function to display the results in a new window
def display_results(found_devices):
    # Create a new window
    results_window = tk.Toplevel(window)
    results_window.title("Search Results")

    # Create a text widget to display the results
    results_text = tk.Text(results_window, height=20, width=80)
    results_text.grid()

    # Insert the results into the text widget
    for device in found_devices:
        results_text.insert(tk.END, f"Device Name: {device['MachineName']}\n")
        results_text.insert(tk.END, f"Company: {device['CustomerName']}\n")
        results_text.insert(tk.END, f"Domain Name: {device['DomainName']}\n")
        results_text.insert(tk.END, f"OS: {device['OS']}\n")
        results_text.insert(tk.END, f"OS Type: {device['OSType']}\n")
        results_text.insert(tk.END, f"LAN IP: {device['IpAddresses']}\n")
        results_text.insert(tk.END, f"WAN IP: {device['ReportedFromIP']}\n")
        results_text.insert(tk.END, f"Online Status: {'Online' if device['Online'] else 'Offline'}\n")
        results_text.insert(tk.END, f"Logged in Users: {device['CurrentLoggedUsers']}\n")
        results_text.insert(tk.END, f"Last Reboot: {device['LastRebootTime']}\n")
        results_text.insert(tk.END, f"Serial Number: {device['VendorSerialNumber']}\n")
        results_text.insert(tk.END, f"Windows Serial Number: {device['WindowsSerialNumber']}\n")
        results_text.insert(tk.END, f"Processor: {device['Processor']}\n")
        results_text.insert(tk.END, f"Memory: {device['Memory']}\n")
        results_text.insert(tk.END, f"Vendor: {device['Vendor']}\n")
        results_text.insert(tk.END, f"Model: {device['VendorBrandModel']}\n")
        results_text.insert(tk.END, f"GPU: {device['Display']}\n")
        results_text.insert(tk.END, f"************************\n")


        # Insert other device information as needed
def fetch_device_information(search_options, search_values, teams_output, csv_output, online_only):
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
            subfolder_name = config['CSV']['filepath']
            if not os.path.exists(subfolder_name):
                os.makedirs(subfolder_name)
            csv_filename = os.path.join(subfolder_name,f"Device_report_{current_datetime}.csv")
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
def search_button_clicked():
    # Get the selected search options and values
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



    # Check if any search options were selected
    if not search_options:
        messagebox.showwarning("Warning", "Please Enter a value for at least one search option.")
        return

    # Fetch device information based on the selected options
    fetch_device_information(search_options, search_values, teams_output_var.get(), csv_output_var.get(), online_only)


# Create the main window
window = tk.Tk()
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
options_frame.grid(row=2, column=1, padx=10, pady=10, sticky="w")
options = config.options('SearchOptions')
# Create search option variables and value entry widgets
option_vars = []
value_entries = []
num_options = len(config.options('SearchOptions'))
options_per_column = min(num_options, 10)
options_remaining = num_options

for i, option in enumerate(config.options('SearchOptions')):
    option_var = tk.StringVar()
    option_var.set(config['SearchOptions'][option])
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
information_frame = tk.LabelFrame(bonus_frame, text="Informations")
information_frame.grid(row=1,column=1,columnspan=2, padx=10, pady=10)
OStypeinfo = tk.Label(information_frame, text="Supported OS Types: Server, Work Station, Domain Controller")
OStypeinfo.grid()

def button_click():
    try:
        # Replace 'path_to_executable' with the actual path to your executable
        subprocess.run(['snmp.exe'])
    except Exception as e:
        # Handle any exceptions that occur during execution
        print(f"Error: {e}")

modules_frame = tk.LabelFrame(bonus_frame, text="Modules")
modules_frame.grid(row=2,column=1,columnspan=2, padx=10, pady=10)

launch_button = tk.Button(modules_frame, text="SNMP Report", command=button_click)
launch_button.grid(row=2,padx=10, pady=10)
def button_click2():
    try:
        # Replace 'path_to_executable' with the actual path to your executable
        subprocess.run(['simplesearch.exe'])
    except Exception as e:
        # Handle any exceptions that occur during execution
        print(f"Error: {e}")


launch2_button = tk.Button(modules_frame, text="Simple Report", command=button_click2)
launch2_button.grid(row=2, column=2, padx=10, pady=10)
def button_click3():
    try:
        # Replace 'path_to_executable' with the actual path to your executable
        subprocess.run(['configure.exe'])
    except Exception as e:
        # Handle any exceptions that occur during execution
        print(f"Error: {e}")


launch3_button = tk.Button(modules_frame, text="Configuration", command=button_click3)
launch3_button.grid(row=2, column=3, padx=10, pady=10)

# Create a frame for the Atera API Key
#api_key_frame = tk.LabelFrame(configuration_frame, text="Atera API Key (Required)")
#api_key_frame.grid(padx=10, pady=10)
# Create an entry field for the API key
#api_key_entry = tk.Entry(api_key_frame, width=50, )
#api_key_entry.grid(padx=10, pady=10)

# Create a frame for the Webhook
#webhook_frame = tk.LabelFrame(configuration_frame, text="Teams Webhook URL (Optional)")
#webhook_frame.grid(padx=10, pady=10)
# Create an entry field for Webhook
#webhook_entry = tk.Entry(webhook_frame, width=50)
#webhook_entry.grid(padx=10, pady=10)
# Create a frame for the Filepath
#filepath_frame = tk.LabelFrame(configuration_frame, text="CSV Export Path (Required)")
#filepath_frame.grid(padx=10, pady=10)
# Create an entry field for FilePath
#filepath_entry = tk.Entry(filepath_frame, width=50)
#filepath_entry.grid(padx=10, pady=10)

# Function to handle the save API key button click event
def load_api_key():
    # Load the config file
    config.read('config.ini')

    # Get the API key from the config file
    if 'API' in config and 'api_key' in config['API']:
        api_key = config['API']['api_key']
    #    api_key_entry.insert(0, api_key)

    if 'SEARCH' in config and 'search_option' in config['SEARCH']:
        search_option = config['SEARCH']['search_option']
        option_var.set(search_option)

# Load the API key when the program starts
load_api_key()


# Function to load the Webhook from the config file
def load_webhook():
    # Load the config file
    config.read('config.ini')

    # Get the Webhook from the config file
    if 'WEBHOOK' in config and 'teams_webhook' in config['WEBHOOK']:
        teams_webhook = config['WEBHOOK']['teams_webhook']

# Load the Webhook when the program starts
load_webhook()

# Function to load the Webhook from the config file
def load_filepath():
    # Load the config file
    config.read('config.ini')

    # Get the Webhook from the config file
    if 'CSV' in config and 'filepath' in config['CSV']:
        subfolder_name = config['CSV']['filepath']

# Load the Filepath when the program starts
load_filepath()

# Create a save config  button
#save_config_button = tk.Button(configuration_frame, text="Save Configuration",command=lambda: [save_filepath(), save_webhook(), save_api_key()])
#save_config_button.grid(padx=10, pady=10)




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
csv_output_var = tk.BooleanVar(value=True)
csv_output_checkbutton = tk.Checkbutton(output_frame, text="Output to CSV", variable=csv_output_var)
csv_output_checkbutton.grid(padx=5, pady=5)




# Create a search button
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
