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

window = tk.Tk()
window.title("AARG Configuration")


configuration_frame = tk.LabelFrame(window, text="Configuration")
configuration_frame.grid(row=3, column=2, sticky="n", padx=10, pady=10)


# Create a frame for the Atera API Key
api_key_frame = tk.LabelFrame(configuration_frame, text="Atera API Key (Required)")
api_key_frame.grid(padx=10, pady=10)
# Create an entry field for the API key
api_key_entry = tk.Entry(api_key_frame, width=50, )
api_key_entry.grid(padx=10, pady=10)

# Create a frame for the Webhook
webhook_frame = tk.LabelFrame(configuration_frame, text="Teams Webhook URL (Optional)")
webhook_frame.grid(padx=10, pady=10)
# Create an entry field for Webhook
webhook_entry = tk.Entry(webhook_frame, width=50)
webhook_entry.grid(padx=10, pady=10)
# Create a frame for the Filepath
filepath_frame = tk.LabelFrame(configuration_frame, text="CSV Export Path (Required)")
filepath_frame.grid(padx=10, pady=10)
# Create an entry field for FilePath
filepath_entry = tk.Entry(filepath_frame, width=50)
filepath_entry.grid(padx=10, pady=10)

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
save_config_button.grid(padx=10, pady=10)

# Start the main loop
window.mainloop()
