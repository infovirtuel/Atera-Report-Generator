import requests
import json
import csv
import tkinter as tk
import configparser
import datetime
from tkinter import messagebox
from PIL import ImageTk, Image
import os
from tkinter import font


config = configparser.ConfigParser()
config.read('config.ini')



# Atera API endpoints for Device Agents
base_url = "https://app.atera.com"
devices_endpoint = "/api/v3/devices/snmpdevices"

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
    results_text.pack()

    # Insert the results into the text widget
    for device in found_devices:
        results_text.insert(tk.END, f"Device Name: {device['Name']}\n")
        results_text.insert(tk.END, f"DeviceID: {device['DeviceID']}\n")
        results_text.insert(tk.END, f"CustomerName: {device['CustomerName']}\n")
        results_text.insert(tk.END, f"Online?: {device['Online']}\n")
        results_text.insert(tk.END, f"HostName: {device['Hostname']}\n")
        results_text.insert(tk.END, f"Type: {device['Type']}\n")
        results_text.insert(tk.END, f"Security: {device['SecurityLevel']}\n")
        results_text.insert(tk.END, f"************************\n")


        # Insert other device information as needed

# Function to fetch device information
def fetch_device_information(search_option, search_value, teams_output, csv_output, online_only):
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
                if search_option == "1":
                    for device in devices:
                        if device["Name"] is not None and search_value.lower() in device["Name"].lower():
                            if online_only and not device["Online"]:
                                continue  # Skip offline devices if checkbox is checked
                            found_devices.append(device)

                elif search_option == "2" and str(device["DeviceID"]) == search_value:
                    if online_only and not device["Online"]:
                        continue  # Skip offline devices if checkbox is checked
                    found_devices.append(device)

                elif search_option == "3":
                    for device in devices:
                        if device["CustomerName"] is not None and search_value.lower() in device["CustomerName"].lower():
                            if online_only and not device["Online"]:
                                continue  # Skip offline devices if checkbox is checked
                            found_devices.append(device)

                elif search_option == "4":
                    for device in devices:
                        if device["Hostname"] is not None and search_value.lower() in device["Hostname"].lower():
                            if online_only and not device["Online"]:
                                continue  # Skip offline devices if checkbox is checked
                            found_devices.append(device)

                elif search_option == "5":
                    for device in devices:
                        if device["Type"] is not None and search_value.lower() in device["Type"].lower():
                            if online_only and not device["Online"]:
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
            subfolder_name = config['CSV']['filepath']
            if not os.path.exists(subfolder_name):
                os.makedirs(subfolder_name)
            csv_filename = os.path.join(subfolder_name,f"snmp_report_{current_datetime}.csv")
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
def search_button_click():
    search_option = search_option_var.get()
    search_value = search_value_entry.get().strip()
    teams_output = teams_output_var.get()
    csv_output = csv_output_var.get()
    online_only = online_only_var.get()

    # Save the selected option to the config file
    config['SEARCH'] = {'search_option': search_option}
    with open('config.ini', 'w') as configfile:
        config.write(configfile)

    if search_value:
        fetch_device_information(search_option, search_value, teams_output, csv_output, online_only)
    else:
        messagebox.showwarning("Warning", "Please enter a search value.")

# Create the main window
window = tk.Tk()
window.title("Atera SNMP Report Generator")
images_folder = "images"
#image_path = os.path.join(images_folder, "Atera_logo.jpg")
image_path = "images/logo.png"
image = Image.open(image_path)
image = image.resize((300, 125), Image.LANCZOS)
# Create an ImageTk object to display the image in the GUI
photo = ImageTk.PhotoImage(image)

# Create a label to display the image
image_label = tk.Label(window, image=photo)
image_label.pack()
# Create a frame for the search value
search_value_frame = tk.LabelFrame(window, text="Search Value (Required)")
search_value_frame.pack(padx=10, pady=10)

# Create an entry field for the search value
search_value_entry = tk.Entry(search_value_frame, width=50)
search_value_entry.pack(padx=5, pady=5)
search_value_entry.insert(0, "Ex. fortigate client1")
# Create a frame for the search option
search_option_frame = tk.LabelFrame(window, text="Search Option (Required)")
search_option_frame.pack(padx=10, pady=10)

# Create a radio button for each search option
search_option_var = tk.StringVar(value="1")

search_option_1 = tk.Radiobutton(search_option_frame, text="Device Name", variable=search_option_var, value="1")
search_option_1.pack(anchor="w")
search_option_2 = tk.Radiobutton(search_option_frame, text="DeviceID", variable=search_option_var, value="2")
search_option_2.pack(anchor="w")
search_option_3 = tk.Radiobutton(search_option_frame, text="CustomerName", variable=search_option_var, value="3")
search_option_3.pack(anchor="w")
search_option_4 = tk.Radiobutton(search_option_frame, text="Hostname", variable=search_option_var, value="4")
search_option_4.pack(anchor="w")
search_option_5 = tk.Radiobutton(search_option_frame, text="Device Type", variable=search_option_var, value="5")
search_option_5.pack(anchor="w")
# Add more radio buttons for other search options

# Create a frame for the Information
information_frame = tk.LabelFrame(window, text="Informations")
information_frame.pack(padx=10, pady=10)


Devicetypeinfo = tk.Label(information_frame, text="Device Types: Printer, Firewall, Other")
Devicetypeinfo.pack(padx=10)
hostnameinfo = tk.Label(information_frame, text="Hostname: IP address or DNS name")
hostnameinfo.pack(padx=10)





configuration_frame = tk.LabelFrame(window, text="Configuration")
configuration_frame.pack(padx=10, pady=10)


# Create a frame for the Atera API Key
api_key_frame = tk.LabelFrame(configuration_frame, text="Atera API Key (Required)")
api_key_frame.pack(padx=10, pady=10)
# Create an entry field for the API key
api_key_entry = tk.Entry(api_key_frame, width=50)
api_key_entry.pack(padx=5, pady=5)

# Create a frame for the Webhook
webhook_frame = tk.LabelFrame(configuration_frame, text="Teams Webhook URL (Optional)")
webhook_frame.pack(padx=10, pady=10)
# Create an entry field for Webhook
webhook_entry = tk.Entry(webhook_frame, width=50)
webhook_entry.pack(padx=5, pady=5)
# Create a frame for the Filepath
filepath_frame = tk.LabelFrame(configuration_frame, text="CSV Export Path (Required)")
filepath_frame.pack(padx=10, pady=10)
# Create an entry field for FilePath
filepath_entry = tk.Entry(filepath_frame, width=50)
filepath_entry.pack(padx=5, pady=5)


# Function to handle the save API key button click event
def save_api_key():
    api_key = api_key_entry.get()

    # Update the config file with the API key
    config['API'] = {'api_key': api_key}
    with open('config.ini', 'w') as configfile:
        config.write(configfile)

    messagebox.showinfo("ATERA API Key", "Atera API Key saved successfully.")

# Function to load the API key from the config file
def load_api_key():
    # Load the config file
    config.read('config.ini')

    # Get the API key from the config file
    if 'API' in config and 'api_key' in config['API']:
        api_key = config['API']['api_key']
        api_key_entry.insert(0, api_key)

    if 'SEARCH' in config and 'search_option' in config['SEARCH']:
        search_option = config['SEARCH']['search_option']
        search_option_var.set(search_option)

# Load the API key when the program starts
load_api_key()




# Function to handle the save Webhook button click event
def save_webhook():
    teams_webhook = webhook_entry.get()

    # Update the config file with the API key
    config['WEBHOOK'] = {'teams_webhook': teams_webhook}
    with open('config.ini', 'w') as configfile:
        config.write(configfile)

    messagebox.showinfo("TEAMS WEBHOOK URL", "Teams Webhook URL saved successfully")

# Function to load the Webhook from the config file
def load_webhook():
    # Load the config file
    config.read('config.ini')

    # Get the Webhook from the config file
    if 'WEBHOOK' in config and 'teams_webhook' in config['WEBHOOK']:
        teams_webhook = config['WEBHOOK']['teams_webhook']
        webhook_entry.insert(0, teams_webhook)

# Load the Webhook when the program starts
load_webhook()





# Function to handle the save filepath button click event
def save_filepath():
    subfolder_name = filepath_entry.get()

    # Update the config file with the API key
    config['CSV'] = {'filepath': subfolder_name}
    with open('config.ini', 'w') as configfile:
        config.write(configfile)

    messagebox.showinfo("CSV EXPORT PATH", "CSV Export Path saved successfully")

# Function to load the Webhook from the config file
def load_filepath():
    # Load the config file
    config.read('config.ini')

    # Get the Webhook from the config file
    if 'CSV' in config and 'filepath' in config['CSV']:
        subfolder_name = config['CSV']['filepath']
        filepath_entry.insert(0, subfolder_name)

# Load the Filepath when the program starts
load_filepath()



# Create a save config  button
save_config_button = tk.Button(configuration_frame, text="Save Configuration",command=lambda: [save_filepath(), save_webhook(), save_api_key()])
save_config_button.pack(side=tk.TOP, padx=10, pady=10)

output_frame = tk.LabelFrame(window, text="Output")
output_frame.pack(padx=10, pady=10)

# Create a checkbox for Online Only Output
online_only_var = tk.IntVar()
online_only_checkbox = tk.Checkbutton(output_frame, text="Output Online Devices", variable=online_only_var)
online_only_checkbox.pack()
# Create a checkbox for Teams output
teams_output_var = tk.BooleanVar(value=False)
teams_output_checkbutton = tk.Checkbutton(output_frame, text="Output to Teams", variable=teams_output_var)
teams_output_checkbutton.pack(side=tk.TOP, padx=10, pady=10)
# Create a checkbox for CSV output
csv_output_var = tk.BooleanVar(value=True)
csv_output_checkbutton = tk.Checkbutton(output_frame, text="Output to CSV", variable=csv_output_var)
csv_output_checkbutton.pack(side=tk.TOP, padx=10, pady=10)


# Create a search button
custom_font = font.Font(size=16)
search_button = tk.Button(output_frame, command=search_button_click, width=231, height=50, font=custom_font, relief=tk.FLAT, bd=0 )
search_button.pack(side=tk.BOTTOM, padx=15, pady=15)
images_folder = "images"
#searchbutton_path = os.path.join(images_folder, "generate.png")
searchbutton_path = "images/generate.png"
button_image = tk.PhotoImage(file=searchbutton_path)
resized_image = button_image.subsample(1)  # Resize the image by a factor of 2
search_button.config(image=resized_image, compound=tk.CENTER)



# Start the main loop
window.mainloop()
