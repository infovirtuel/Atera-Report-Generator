import requests
import json
import csv
import datetime
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from datetime import datetime as datetime1
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table , TableStyle, Image as pdf_image, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import sys
import ssl as sslmail
import ast
import pandas as pd
import shutil
import configparser
from configparser import ConfigParser
import traceback
import nicegui
from nicegui import ui, app
import socket
from fastapi.responses import RedirectResponse
import hashlib
from nicegui.events import ValueChangeEventArguments
from nicegui.events import KeyEventArguments
import secrets
import string
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import asyncio
import pyAesCrypt
import pyotp
import time
import ssl
import sqlite3
import psycopg2
from psycopg2 import pool

connection_pool = psycopg2.pool.SimpleConnectionPool(
    minconn=1,      # Minimum number of connections
    maxconn=100,     # Maximum number of connections
    dbname="postgres",
    user="postgres",
    password="11Yealink88**",
    host="127.0.0.1",
    port="5432"
)


def generate_random_string(length):
    alphabet = string.ascii_letters + string.digits
    random_string = ''.join(secrets.choice(alphabet) for _ in range(length))
    return random_string

base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
logo_img = os.path.join(base_path, 'source_web', 'images', 'banner3.png')
login_img = os.path.join(base_path, 'source_web', 'images', 'banner-alt.png')
script_path = os.path.dirname(os.path.abspath(__file__))
server_path = os.path.join(script_path, "server")
cert_path = os.path.join(server_path, "certs")
report_path = os.path.join(server_path, "reports")
cachepath = os.path.join(server_path, "arg_cache")
global_configs_folder = os.path.join(server_path, "global_configs")
user_cache_folder = os.path.join(cachepath, "user_cache")
os.makedirs(server_path, exist_ok=True)
os.makedirs(cert_path, exist_ok=True)
os.makedirs(cachepath, exist_ok=True)
os.makedirs(user_cache_folder, exist_ok=True)
os.makedirs(report_path, exist_ok=True)
os.makedirs(global_configs_folder, exist_ok=True)

global_config_file = os.path.join(global_configs_folder, 'globalconfig.ini')
if not os.path.exists(global_config_file):
    with open(global_config_file, 'w') as file:
        file.write('')  # You can add initial contents if needed

certificate = os.path.join(cert_path, 'certificate.crt')
key = os.path.join(cert_path,'private.key')

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=certificate, keyfile=key)


def new_user(username, password, nickname, salt, totp, tier, role):
    conn = connection_pool.getconn()
    cursor = conn.cursor()
    query_check = "SELECT * FROM users WHERE username = %s"
    values_check = (username,)
    cursor.execute(query_check, values_check)
    existing_user = cursor.fetchone()
    if existing_user:
        ui.notify('Username already exists', color='negative')
        return

    query_check_nickname = "SELECT * FROM users WHERE nickname = %s"
    values_check_nickname = (nickname,)
    cursor.execute(query_check_nickname, values_check_nickname)
    existing_nickname = cursor.fetchone()

    if existing_nickname:
        ui.notify('Nickname already exists', color='negative')
        return

    query = "INSERT INTO users (username, password, nickname, salt, totp, tier, role) VALUES (%s, %s, %s, %s, %s, %s, %s)"
    values = (username, password, nickname, salt, totp, tier, role)
    cursor.execute(query, values)
    conn.commit()
    cursor.close()  # Close the cursor
    connection_pool.putconn(conn)

def geolocation_info(querywanip):
    with connection_pool.getconn() as conn:
        cursor = conn.cursor()

        try:
            query_check = "SELECT ip, status, country, regionName, city, isp FROM geocache WHERE ip = %s"
            values_check = (querywanip,)
            cursor.execute(query_check, values_check)
            existing_value = cursor.fetchone()

            if existing_value:
                ip, status, country, regionName, city, isp = existing_value
                if status != "fail":
                    geolocation_variables = [city, regionName, country]
                    geolocation = ", ".join(geolocation_variables)
                    return str(geolocation), str(isp)
                else:
                    geolocation = "INVALID"
                    isp = "INVALID"
                    return str(geolocation), str(isp)
            else:
                ip_api_url = "https://api.techniknews.net/ipgeo/"

                def make_geolocation_request(device_wan_ip, method="GET", params=None):
                    geolocationurl = ip_api_url + device_wan_ip
                    headers = {
                        "Accept": "application/json",
                    }

                    response = requests.request(method, geolocationurl, headers=headers, params=params)
                    response.raise_for_status()
                    return response.json()

                geolocation_data = make_geolocation_request(device_wan_ip=querywanip, params=None)
                status = geolocation_data.get("status")

                if geolocation_data is not None and status == "fail":
                    geolocation = "INVALID"
                    isp = "INVALID"
                    return str(geolocation), str(isp)

                if geolocation_data is not None and status != "fail":
                    ip = geolocation_data.get("ip")
                    city = geolocation_data.get("city")
                    regionName = geolocation_data.get("regionName")
                    country = geolocation_data.get("country")
                    isp = geolocation_data.get("isp")
                    geolocation_variables = [city, regionName, country]
                    geolocation = ", ".join(geolocation_variables)

                    query = "INSERT INTO geocache (ip, status, country, regionName, city, isp) VALUES (%s, %s, %s, %s, %s, %s)"
                    values = (ip, status, country, regionName, city, isp)
                    cursor.execute(query, values)
                    conn.commit()
                    return str(geolocation), str(isp)
        finally:
            cursor.close()  # Close the cursor
            connection_pool.putconn(conn)

def eolcache_sql_update():
    current_year = datetime.datetime.now().year
    current_year_str = str(current_year)
    current_month = datetime.datetime.now().month
    current_month_str = str(current_month)
    month_cache = current_year_str + "," + current_month_str
    endoflife_url = "https://endoflife.date/api/"
    endoflife_windows_endpoint = "windows.json"
    endoflife_windows_server_endpoint = "windowsserver.json"
    endoflife_macos_endpoint = "macos.json"

    def make_endoflife_request(endpoint, method="GET", params=None):
        url = endoflife_url + endpoint
        headers = {
            "Accept": "application/json",
        }
        response = requests.request(method, url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()

    with connection_pool.getconn() as conn:
        cursor = conn.cursor()

        try:
            # Check if data for the current month already exists
            query_check = "SELECT date, data FROM eolcache"
            cursor.execute(query_check)
            existing_values = cursor.fetchall()

            # Flag to determine if data needs to be refetched
            refetch_data = True

            for cache_date, data in existing_values:
                if cache_date == month_cache:
                    refetch_data = False
                    break

            if refetch_data:
                # Delete the existing entries
                query_delete = "DELETE FROM eolcache"
                cursor.execute(query_delete)

                # Fetch and insert the new data
                windows_eol_data = make_endoflife_request(endoflife_windows_endpoint, params=None)
                ws_eol_data = make_endoflife_request(endoflife_windows_server_endpoint, params=None)
                mac_eol_data = make_endoflife_request(endoflife_macos_endpoint, params=None)

                # Convert dictionaries to JSON strings
                windows_eol_data_json = json.dumps(windows_eol_data)
                ws_eol_data_json = json.dumps(ws_eol_data)
                mac_eol_data_json = json.dumps(mac_eol_data)

                query = "INSERT INTO eolcache (name, date, data) VALUES (%s, %s, %s)"
                values = ("windows", month_cache, windows_eol_data_json)
                cursor.execute(query, values)

                query = "INSERT INTO eolcache (name, date, data) VALUES (%s, %s, %s)"
                values = ("windowsserver", month_cache, ws_eol_data_json)
                cursor.execute(query, values)

                query = "INSERT INTO eolcache (name, date, data) VALUES (%s, %s, %s)"
                values = ("macos", month_cache, mac_eol_data_json)
                cursor.execute(query, values)

                conn.commit()
        finally:
            cursor.close()
            connection_pool.putconn(conn)



def get_eol_cache(ostable):
    conn = connection_pool.getconn()
    cursor = conn.cursor()

    try:
        # Retrieve the inserted user configuration
        query_get = "SELECT data FROM eolcache WHERE name = %s"
        values_get = (ostable,)
        cursor.execute(query_get, values_get)
        eol_data = cursor.fetchone()

        if eol_data:
            eol_json = json.dumps(eol_data[0])  # Convert the data to a JSON string
            return eol_json
        else:
            return None

    finally:
        cursor.close()  # Close the cursor
        connection_pool.putconn(conn)

def new_user_config(username):
    conn = connection_pool.getconn()
    cursor = conn.cursor()

    query_check = "SELECT * FROM user_configs WHERE username = %s"
    values_check = (username,)
    cursor.execute(query_check, values_check)
    existing_user = cursor.fetchone()
    if existing_user:
        return
    webhook = None
    geolocation = False
    geolocation_provider = "https://api.techniknews.net/ipgeo/"
    eol = True
    onlineonly = False
    excel_output = False
    cachemode = True
    smtp_server = "smtp.office365.com"
    smtp_port = "587"
    smtp_username = "defaultsender@default.com"
    smtp_password = None
    starttls = True
    sslvalue = False
    sender_email = "defaultsender@default.com"
    recipient_email = "defaultrecipient@default.com"
    subject = "ARG Report Results"
    body = "Please find the attached results file"
    query = "INSERT INTO user_configs (username, webhook, geolocation, geolocation_provider, eol, onlineonly, excel_output, cachemode, smtp_server, smtp_port, smtp_username, smtp_password, starttls, ssl, sender_email, recipient_email, subject, body) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    values = (username, webhook, geolocation, geolocation_provider, eol, onlineonly, excel_output, cachemode, smtp_server, smtp_port, smtp_username, smtp_password, starttls, sslvalue, sender_email, recipient_email, subject, body )
    cursor.execute(query, values)
    conn.commit()
    cursor.close()  # Close the cursor
    connection_pool.putconn(conn)

def update_user_config(username, webhook, geolocation, geolocation_provider, eol, onlineonly, excel_output, cachemode,
                       smtp_server, smtp_port, smtp_username, smtp_password, starttls, sslvalue, sender_email,
                       recipient_email, subject, body):
    conn = connection_pool.getconn()
    cursor = conn.cursor()

    query = '''
    UPDATE user_configs 
    SET webhook = %s, geolocation = %s, geolocation_provider = %s, eol = %s, onlineonly = %s, excel_output = %s, cachemode = %s,
        smtp_server = %s, smtp_port = %s, smtp_username = %s, smtp_password = %s, starttls = %s, ssl = %s, sender_email = %s,
        recipient_email = %s, subject = %s, body = %s
    WHERE username = %s
    '''

    values = (
        webhook, geolocation, geolocation_provider, eol, onlineonly, excel_output, cachemode, smtp_server,
        smtp_port, smtp_username, smtp_password, starttls, sslvalue, sender_email, recipient_email, subject, body,
        username
    )

    cursor.execute(query, values)
    conn.commit()
    cursor.close()  # Close the cursor
    connection_pool.putconn(conn)



def get_user_config(username):
    conn = connection_pool.getconn()
    cursor = conn.cursor()
    # Retrieve the inserted user configuration
    query_get = "SELECT * FROM user_configs WHERE username = %s"
    values_get = (username,)
    cursor.execute(query_get, values_get)
    user_config = cursor.fetchone()
    cursor.close()  # Close the cursor
    connection_pool.putconn(conn)
    return user_config

def get_api_key(username):
    conn = connection_pool.getconn()
    cursor = conn.cursor()
    # Retrieve the inserted user configuration
    query_get = "SELECT encrypted_api_key FROM user_configs WHERE username = %s"
    values_get = (username,)
    cursor.execute(query_get, values_get)
    encrypted_api_key = cursor.fetchone()
    cursor.close()  # Close the cursor
    connection_pool.putconn(conn)
    return encrypted_api_key[0] if encrypted_api_key else None

def set_api_key(username, encrypted_api_key):
    conn = connection_pool.getconn()
    cursor = conn.cursor()
    query = "UPDATE user_configs SET encrypted_api_key = %s WHERE username = %s"
    values = (encrypted_api_key, username)
    cursor.execute(query, values)
    cursor.close()  # Close the cursor
    connection_pool.putconn(conn)


def verify_login(username):
    conn = connection_pool.getconn()
    cursor = conn.cursor()

    query = "SELECT tier, nickname, salt, totp, role, password FROM users WHERE username = %s"
    values = (username,)
    cursor.execute(query, values)
    result = cursor.fetchone()
    cursor.close()  # Close the cursor
    connection_pool.putconn(conn)

    if result:
        tier, nickname, salt, totp, role, password = result
        match = True
    else:
        match = False
        tier, nickname, salt, totp, role, password = None, None, None, None, None, None

    return tier, nickname, salt, totp, role, password, match





def get_username_by_nickname(nickname):
    conn = connection_pool.getconn()
    cursor = conn.cursor()
    query = "SELECT username FROM users WHERE nickname = %s"
    values = (nickname,)
    cursor.execute(query, values)
    result = cursor.fetchone()
    cursor.close()  # Close the cursor
    connection_pool.putconn(conn)
    if result:
        return result[0]

def get_salt(username):
    conn = connection_pool.getconn()
    cursor = conn.cursor()
    query = "SELECT salt FROM users WHERE username = %s"
    values = (username,)
    cursor.execute(query, values)
    salt = cursor.fetchone()
    cursor.close()  # Close the cursor
    connection_pool.putconn(conn)
    return salt[0] if salt else None

def update_salt(username, new_salt):
    conn = connection_pool.getconn()
    cursor = conn.cursor()
    query = "UPDATE users SET salt = %s WHERE username = %s"
    values = (new_salt, username)
    cursor.execute(query, values)
    conn.commit()
    cursor.close()  # Close the cursor
    connection_pool.putconn(conn)

def update_password(username, new_password):
    conn = connection_pool.getconn()
    cursor = conn.cursor()
    query = "UPDATE users SET password = %s WHERE username = %s"
    values = (new_password, username)
    cursor.execute(query, values)
    conn.commit()
    cursor.close()  # Close the cursor
    conn.close()  # Close the connection
def update_totp(username, new_totp):
    conn = connection_pool.getconn()
    cursor = conn.cursor()
    query = "UPDATE users SET totp = %s WHERE username = %s"
    values = (new_totp, username)
    cursor.execute(query, values)
    conn.commit()
    cursor.close()  # Close the cursor
    connection_pool.putconn(conn)

def update_tier(username, new_tier):
    conn = connection_pool.getconn()
    cursor = conn.cursor()
    query = "UPDATE users SET tier = %s WHERE username = %s"
    values = (new_tier, username)
    cursor.execute(query, values)
    conn.commit()
    cursor.close()  # Close the cursor
    connection_pool.putconn(conn)
def update_role(username, new_role):
    conn = connection_pool.getconn()
    cursor = conn.cursor()
    query = "UPDATE users SET role = %s WHERE username = %s"
    values = (new_role, username)
    cursor.execute(query, values)
    conn.commit()
    cursor.close()  # Close the cursor
    connection_pool.putconn(conn)



def delete_user(username):
    conn = connection_pool.getconn()
    cursor = conn.cursor()
    query = "DELETE FROM users WHERE username = %s"
    values = (username,)
    cursor.execute(query, values)
    conn.commit()
    cursor.close()  # Close the cursor
    connection_pool.putconn(conn)

def delete_user_config(username):
    conn = connection_pool.getconn()
    cursor = conn.cursor()
    query = "DELETE FROM user_configs WHERE username = %s"
    values = (username,)
    cursor.execute(query, values)
    conn.commit()
    cursor.close()  # Close the cursor
    connection_pool.putconn(conn)

def delete_totp(username):
    conn = connection_pool.getconn()
    cursor = conn.cursor()
    query = "UPDATE users SET totp = NULL WHERE username = %s"
    values = (username,)
    cursor.execute(query, values)
    conn.commit()
    cursor.close()  # Close the cursor
    connection_pool.putconn(conn)

def delete_api_key(username):
    conn = connection_pool.getconn()
    cursor = conn.cursor()
    query = "UPDATE user_configs SET encrypted_api_key = NULL WHERE username = %s"
    values = (username,)
    cursor.execute(query, values)
    conn.commit()
    cursor.close()  # Close the cursor
    connection_pool.putconn(conn)


def get_role_user_tier():
    conn = connection_pool.getconn()
    cursor = conn.cursor()
    query_user_data = "SELECT nickname, role, tier FROM users"
    cursor.execute(query_user_data)
    user_data = cursor.fetchall()
    cursor.close()  # Close the cursor
    connection_pool.putconn(conn)
    return user_data



def create_user_database():
    # Connect to the SQLite database (create it if it doesn't exist)
    conn = connection_pool.getconn()
    cursor = conn.cursor()
    # Create the users table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT,
            password TEXT,
            nickname TEXT,
            salt TEXT,
            totp TEXT,
            tier TEXT,
            role TEXT

        )
    ''')
    conn.commit()
    cursor.close()  # Close the cursor
    connection_pool.putconn(conn)

def create_user_config_database():
    # Connect to the PostgreSQL database
    conn = connection_pool.getconn()
    cursor = conn.cursor()

    # Create the users table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_configs (
            id SERIAL PRIMARY KEY,
            username TEXT,
            webhook TEXT,
            encrypted_api_key BYTEA,
            geolocation BOOLEAN,
            geolocation_provider TEXT,
            eol BOOLEAN,
            onlineonly BOOLEAN,
            excel_output BOOLEAN,
            cachemode BOOLEAN,
            smtp_server TEXT,
            smtp_port TEXT,
            smtp_username TEXT,
            smtp_password TEXT,
            starttls BOOLEAN,
            ssl BOOLEAN,
            sender_email TEXT,
            recipient_email TEXT,
            subject TEXT,
            body TEXT
        )
    ''')

    # Commit the changes and close the connection
    conn.commit()
    cursor.close()  # Close the cursor
    connection_pool.putconn(conn)

create_user_config_database()
def create_cache_db():
    conn = connection_pool.getconn()
    cursor = conn.cursor()

    # Create a table to store PDF files if it doesn't exist

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS geocache (
            id SERIAL PRIMARY KEY,
            ip TEXT,
            status TEXT,
            country TEXT,
            regionName TEXT,
            city TEXT,
            isp TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS eolcache (
            id SERIAL PRIMARY KEY,
            name TEXT,
            date TEXT,
            data JSONB
        )
    ''')

    conn.commit()
    cursor.close()  # Close the cursor
    connection_pool.putconn(conn)


create_cache_db()
create_user_database()

eolcache_sql_update()
eol_response_json = get_eol_cache(ostable="windows")
eol_response1_json = get_eol_cache(ostable="windowsserver")
eol_response3_json = get_eol_cache(ostable="macos")

globalconfig = configparser.ConfigParser()
globalconfig.read(global_config_file)
default_password = "ilovearg2023!"
default_username = "admin"
default_nickname = "Administrator"
default_tier = "unlimited"
default_role = "admin"
default_totp = "3M6XLEAEVSL4RIESY7STX56ZLPQYIGJO"

default_salt = secrets.token_hex(16)
default_hashed_username = hashlib.sha3_512(default_username.encode()).hexdigest()
default_hashed_password = hashlib.sha3_512((default_password + default_salt).encode()).hexdigest()

new_user(default_hashed_username, default_hashed_password, default_nickname, default_salt, default_totp,default_tier, default_role)

def create_global_config():
    if 'GENERAL' not in globalconfig:
        globalconfig['GENERAL'] = {}
    if 'registration' not in globalconfig['GENERAL']:
        globalconfig['GENERAL']['registration'] = "True"
    if 'cachemode' not in globalconfig['GENERAL']:
        globalconfig['GENERAL']['cachemode'] = "True"
    if 'teams' not in globalconfig['GENERAL']:
        globalconfig['GENERAL']['teams'] = "True"
    if 'email' not in globalconfig['GENERAL']:
        globalconfig['GENERAL']['email'] = "True"
    if 'forcecache' not in globalconfig['GENERAL']:
        globalconfig['GENERAL']['forcecache'] = "False"
    if 'darkmode' not in globalconfig['GENERAL']:
        globalconfig['GENERAL']['darkmode'] = "False"
    if 'master_token' not in globalconfig['GENERAL']:
        globalconfig['GENERAL']['master_token'] = generate_random_string(30)

    with open(f'server/global_configs/globalconfig.ini', 'w') as global_config_file:
        globalconfig.write(global_config_file)



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

create_global_config()
master_token = globalconfig['GENERAL']['master_token']
darkmode = globalconfig['GENERAL']['darkmode']

# Create 'API' section in the config file
@ui.page('/', dark= darkmode)
def main_page() -> None:
    if not app.storage.user.get('authenticated', False):
        return RedirectResponse('/login')
    userlogin = app.storage.user["username"]
    agents_data = []
    snmp_data = []
    tcp_data = []
    http_data = []


    new_user_config(userlogin)
    user_config = get_user_config(userlogin)
    encrypted_apikey = get_api_key(userlogin)

    user_report_path = os.path.join(report_path, userlogin)
    os.makedirs(user_report_path, exist_ok=True)
    pdf_path_download = os.path.join(user_report_path, 'pdf')
    csv_path_download = os.path.join(user_report_path, 'csv')
    excel_path_download = os.path.join(user_report_path, 'xlsx')
    if not os.path.exists(pdf_path_download):
        os.makedirs(pdf_path_download)
    if not os.path.exists(csv_path_download):
        os.makedirs(csv_path_download)
    if not os.path.exists(excel_path_download):
        os.makedirs(excel_path_download)

    saved_geolocation_option = bool(user_config[4])
    saved_onlineonly_option = bool(user_config[7])
    saved_webhook_option = str(user_config[2])
    saved_eol_option = bool(user_config[6])
    saved_excel_option = bool(user_config[8])
    saved_cache_mode = bool(user_config[9])
    saved_email_recipient = str(user_config[17])
    saved_email_sender = str(user_config[16])
    saved_email_subject = str(user_config[18])
    saved_email_body = str(user_config[19])
    saved_smtp_server = str(user_config[10])
    saved_smtp_port = str(user_config[11])
    saved_smtp_username = str(user_config[12])
    saved_smtp_password = str(user_config[13])
    saved_ssl_option = bool(user_config[15])
    saved_starttls_option = bool(user_config[14])

    tls_var = saved_starttls_option
    geolocation_var = saved_geolocation_option
    onlineonly_var = saved_onlineonly_option
    webhook_var = saved_webhook_option
    eol_var = saved_eol_option
    excel_var = saved_excel_option
    cache_var = saved_cache_mode
    email_recipient_var = saved_email_recipient
    email_sender_var = saved_email_sender
    email_subject_var = saved_email_subject
    email_body_var = saved_email_body
    smtp_server_var = saved_smtp_server
    smtp_port_var = saved_smtp_port
    smtp_username_var = saved_smtp_username
    ssl_var = saved_ssl_option
    smtp_password_var = saved_smtp_password


    output_mode = None
    chosen_eol_date = None
    base_url = "https://app.atera.com/api/v3/"
    devices_endpoint = "agents"
    snmp_devices_endpoint = "devices/snmpdevices"
    snmp_devices_endpoint2 = "devices/snmpdevice"
    http_devices_endpoint = "devices/httpdevices"
    http_devices_endpoint2 = "devices/httpdevice"
    tcp_devices_endpoint = "devices/tcpdevices"
    tcp_devices_endpoint2 = "devices/tcpdevice"
    endoflife_url = "https://endoflife.date/api/"
    endoflife_windows_endpoint = "windows.json"
    endoflife_windows_server_endpoint = "windowsserver.json"
    endoflife_macos_endpoint = "macos.json"
    endoflife_ubuntu_endpoint = "ubuntu.json"
    endoflife_intel_endpoint = "intel-processors.json"
    ip_api_url = "https://api.techniknews.net/ipgeo/"

    def make_endoflife_request(endpoint, method="GET", params=None):
        url = endoflife_url + endpoint
        headers = {
            "Accept": "application/json",
        }

        response = requests.request(method, url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()


    def make_atera_request(endpoint, method="GET", params=None):
        encrypted_password = app.storage.user.get('encrypted_password')
        hashed_password = hashlib.sha256(encrypted_password.encode()).hexdigest()
        stored_salt = get_salt(userlogin)
        # Generate a key from the hashed password using PBKDF2
        userbytes = bytes(userlogin, 'utf-8')
        tokenbytes = bytes(master_token, 'utf-8')
        saltbytes = bytes(stored_salt, 'utf-8')
        salt = userbytes + tokenbytes + saltbytes
        iterations = 100000  # Adjust the number of iterations to a suitable value
        key_length = 32  # Length of the desired key in bytes
        backend = default_backend()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=iterations,
            backend=backend
        )
        key = base64.urlsafe_b64encode(kdf.derive(hashed_password.encode()))
        # Create a Fernet cipher instance with the key
        cipher = Fernet(key)
        encrypted_api_key2 = bytes(encrypted_apikey)

        decrypted_api_key = cipher.decrypt(encrypted_api_key2).decode()

        url = base_url + endpoint
        headers = {
            "Accept": "application/json",
            "X-Api-Key": decrypted_api_key
        }

        response = requests.request(method, url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()

    def atera_device_delete(endpoint, agentid, method="DELETE", params=None):
        encrypted_password = app.storage.user.get('encrypted_password')
        hashed_password = hashlib.sha256(encrypted_password.encode()).hexdigest()
        stored_salt = get_salt(userlogin)
        # Generate a key from the hashed password using PBKDF2
        userbytes = bytes(userlogin, 'utf-8')
        tokenbytes = bytes(master_token, 'utf-8')
        saltbytes = bytes(stored_salt, 'utf-8')
        salt = userbytes + tokenbytes + saltbytes
        iterations = 100000  # Adjust the number of iterations to a suitable value
        key_length = 32  # Length of the desired key in bytes
        backend = default_backend()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=iterations,
            backend=backend
        )
        key = base64.urlsafe_b64encode(kdf.derive(hashed_password.encode()))
        # Create a Fernet cipher instance with the key
        cipher = Fernet(key)
        encrypted_api_key2 = bytes(encrypted_apikey)

        decrypted_api_key = cipher.decrypt(encrypted_api_key2).decode()

        url = base_url + endpoint + "/" + agentid
        headers = {
            "Accept": "application/json",
            "X-Api-Key": decrypted_api_key
        }

        response = requests.request(method, url, headers=headers, params=params)
        response.raise_for_status()

    def extract_device_information(device, output_mode):
        eolreport = eol_var
        geolocation_option = geolocation_var
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
                if disk['Drive'] == '/':
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
                geolocation, ipisp = geolocation_info(device_wan_ip)
            if not geolocation_option:
                geolocation = ""
                ipisp = ""
            #chosen_eol_date = None
            if eolreport:
                try:

                    eol_response = json.loads(eol_response_json)
                    eol_response1 = json.loads(eol_response1_json)
                    eol_response3 = json.loads(eol_response3_json)


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
        msg['From'] = email_sender_var
        msg['To'] = email_recipient_var
        msg['Subject'] = email_subject_var
        if csv_output:
            attachment = MIMEApplication(open(csv_filename, 'rb').read())
            attachment.add_header('Content-Disposition', 'attachment', filename=csv_filename)
            msg.attach(attachment)
            if excel_var:
                attachment = MIMEApplication(open(excel_filename, 'rb').read())
                attachment.add_header('Content-Disposition', 'attachment', filename=excel_filename)
                msg.attach(attachment)
        if pdf_output:
            attachment = MIMEApplication(open(pdf_filename, 'rb').read())
            attachment.add_header('Content-Disposition', 'attachment', filename=pdf_filename)
            msg.attach(attachment)


        # Add the body text to the email
        msg.attach(MIMEText(email_body_var, 'plain'))
        # Send the email
        context = sslmail.create_default_context(sslmail.Purpose.CLIENT_AUTH)
        context.verify_mode = sslmail.CERT_REQUIRED
        context.load_default_certs(sslmail.Purpose.SERVER_AUTH)

        try:
            if ssl_var:
                with smtplib.SMTP_SSL(smtp_server_var, smtp_port_var, context=context) as server:

                    server.ehlo()
                    server.login(smtp_username_var, smtp_password_var)
                    server.send_message(msg)
            elif tls_var:
                with smtplib.SMTP(smtp_server_var, smtp_port_var) as server:
                    server.ehlo()
                    server.starttls()
                    server.ehlo()
                    server.login(smtp_username_var, smtp_password_var)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(smtp_server_var, smtp_port_var) as server:
                    server.ehlo()
                    server.login(smtp_username_var, smtp_password_var)
                    server.send_message(msg)

            ui.notify(f"Email from {email_sender_var} sent successfully to {email_recipient_var}", type='positive')

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
        # Convert the Adaptive Card to JSON string
        adaptive_card_json = json.dumps(adaptive_card)

        # Post the Adaptive Card to Teams
        teams_webhook = webhook_var
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

    def ui_results(found_devices, output_mode):
        agents_data.clear()
        snmp_data.clear()
        tcp_data.clear()
        http_data.clear()
        for device in found_devices:

            if output_mode == "agents":
                AgentID = device["AgentID"]

                device_name, device_company, device_domain, device_os, device_win_version,\
                    device_type, device_ip, device_wan_ip, device_status, device_currentuser,\
                    device_lastreboot, device_serial, device_windows_serial, device_processor,\
                    device_ram, device_vendor, device_model, device_gpu,\
                    device_os_build, device_online, c_drive_free_gb,\
                    c_drive_used_gb, c_drive_total_gb, c_drive_usage_percent, \
                    geolocation, ipisp, chosen_eol_date = extract_device_information(device, output_mode)
                agents_data.append({'AgentID': AgentID,'device_name': device_name, 'customer': device_company, 'domain': device_domain,
                                    'os': device_os, 'type': device_type, 'ip': device_ip, 'wanip': device_wan_ip,
                                    'status': 'Online' if device_status == True else 'Offline', 'username': device_currentuser,
                                    'diskusage': f"{c_drive_usage_percent:.2f} %",'geolocation': geolocation,
                                    'isp': ipisp, 'eol': chosen_eol_date, 'ram': f"{device_ram:.2f} GB",
                                    'vendor': device_vendor, 'device_model': device_model,
                                    'device_lastreboot': device_lastreboot,
                                    'c_drive_used_gb': f"{c_drive_used_gb:.2f} GB",
                                    'c_drive_free_gb': f"{c_drive_free_gb:.2f} GB",
                                    'c_drive_total_gb': f"{c_drive_total_gb:.2f} GB",
                                    'serial': device_serial,'cpu': device_processor})
                result_table.update()
            if output_mode == "snmp":
                device_name, device_id, device_company, device_hostname, \
                    device_online, device_type, device_security, = extract_device_information(device, output_mode)
                snmp_data.append({'device_name': device_name, 'device_id': device_id,
                                  'device_company': device_company, 'device_hostname': device_hostname,
                                  'status': 'Online' if device_online == True else 'Offline', 'type': device_type,
                                  'security': device_security})
                snmp_result_table.update()

            if output_mode == "http":
                device_name, device_id, device_company, device_url, device_online, \
                    device_pattern, device_patternup = extract_device_information(device, output_mode)
                http_data.append({'device_name': device_name, 'device_id': device_id,
                                  'device_company': device_company, 'device_url': device_url,
                                  'status': 'Online' if device_online == True else 'Offline', 'device_pattern': device_pattern,
                                  'device_patternup': device_patternup})
                http_result_table.update()

            if output_mode == "tcp":
                device_name, device_id, device_company, \
                    device_online, tcp_port = extract_device_information(device, output_mode)
                tcp_data.append({'device_name': device_name, 'device_id': device_id,
                                  'device_company': device_company,
                                  'status': 'Online' if device_online == True else 'Offline', 'tcp_port': tcp_port})
                tcp_result_table.update()




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
        globalconfig.read(global_config_file)
        online_only = onlineonly_var
        cachemode = cache_var
        cache_mode_config = globalconfig['GENERAL']['cachemode']
        forcecachemode = globalconfig['GENERAL']['forcecache']
        current_year = datetime.datetime.now().year
        current_month = datetime.datetime.now().month
        current_day = datetime.datetime.now().day
        cache_directory = f"{user_cache_folder}/{userlogin}/{output_mode}/{current_year}/{current_month}/{current_day}"
        os.makedirs(cache_directory, exist_ok=True)
        try:
            page = 1
            found_devices = []
            # Process all pages of devices
            while True:
                params = {"page": page, "itemsInPage": 50}
                if cachemode and cache_mode_config == "True" or forcecachemode =="True":
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
                else:
                    break
            if found_devices:

                output_results(found_devices, cli_mode,
                               teams_output, csv_output, pdf_output,
                               email_output, search_values, output_mode)

        except Exception as e:

            traceback.print_exc()


    # Function to handle the search button click event


    def output_results(found_devices, cli_mode,
                       teams_output, csv_output, pdf_output, email_output, search_values, output_mode):
        ipadd = get_ip()


        csv_filename = None
        excel_filename = None
        pdf_filename = None
        csv_download = None
        pdf_download = None
        excel_download = None
        bufferSize = 128 * 1024
        encrypted_password = app.storage.user.get('encrypted_password')
        excel_output = excel_var
        current_datetime = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_download = f"{output_mode}_pdf_report_{current_datetime}_pdf"
        csv_download = f"{output_mode}_csv_report_{current_datetime}.csv"
        excel_download = f"{output_mode}_excel_report_{current_datetime}.xlsx"
        pdf_filename = os.path.join(pdf_path_download, f"{pdf_download}")
        csv_filename = os.path.join(csv_path_download, f"{csv_download}")
        excel_filename = os.path.join(excel_path_download, f"{excel_download}")
        ui_results(found_devices, output_mode)
        if pdf_output:

            pdf_results(found_devices, pdf_filename, cli_mode, output_mode)

        if csv_output:
            csv_results(found_devices, csv_filename, cli_mode, output_mode)

            if excel_output:
                if excel_output:

                    csv_encoding = 'latin-1'
                    data = pd.read_csv(csv_filename, encoding=csv_encoding)
                    data.to_excel(excel_filename, index=False, )



        if pdf_output:
            encrypted_filename = pdf_filename + '.crypt'
            decrypted_filename = pdf_filename + '.pdf'
            decrypted_filename_download = pdf_download + '.pdf'
            pyAesCrypt.encryptFile(pdf_filename, encrypted_filename, encrypted_password, bufferSize)
            os.remove(pdf_filename)
            pyAesCrypt.decryptFile(encrypted_filename, decrypted_filename, encrypted_password, bufferSize)
            app.add_static_files(f'/reports/{userlogin}/pdf', pdf_path_download)
            ui.download(f'http://{ipadd}:8080/reports/{userlogin}/pdf/{decrypted_filename_download}')


        if csv_output:
            app.add_static_files(f'/reports/{userlogin}/csv', csv_path_download)
            ui.download(f'http://{ipadd}:8080/reports/{userlogin}/csv/{csv_download}')
            if excel_output:
                app.add_static_files(f'/reports/{userlogin}/xlsx', excel_path_download)
                ui.download(f'http://{ipadd}:8080/reports/{userlogin}/xlsx/{excel_download}')


        if teams_output:
            teams_results(found_devices, search_values, output_mode, cli_mode)

        if email_output:
            email_results(csv_output, pdf_output, csv_filename, pdf_filename, cli_mode, excel_filename)
        # Display the results in a new window
        if pdf_output:
            ui.notify('Your PDF File is ready to download', type='positive')
            ui.timer(10.0, lambda: app.remove_route(f'/reports/{userlogin}/pdf'), once=True)
            ui.timer(10.0, lambda: os.remove(decrypted_filename), once=True)
            #ui.timer(20.0, lambda: os.remove(pdf_filename), once=True)
        if csv_output:
            ui.notify('Your CSV File is ready to download', type='positive')
            ui.timer(10.0, lambda: app.remove_route(f'/reports/{userlogin}/csv'), once=True)
            #ui.timer(20.0, lambda: os.remove(csv_filename), once=True)
            if excel_output:
                ui.notify('Your XLSX File is ready to download', type='positive')
                ui.timer(10.0, lambda: app.remove_route(f'/reports/{userlogin}/xlsx'), once=True)
                #ui.timer(20.0, lambda: os.remove(excel_filename), once=True)
        report_data.clear()
        csv_files = os.listdir(csv_report_path)
        pdf_files = os.listdir(pdf_report_path)
        xlsx_files = os.listdir(xlsx_report_path)
        all_files = csv_files + pdf_files + xlsx_files
        for filename in all_files:
            if filename.endswith('.csv'):
                file_path = os.path.join(csv_report_path, filename)
                creation_time = os.path.getctime(file_path)
                creation_date = datetime1.utcfromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
                report_data.append({'name': filename, 'type': 'CSV', 'creation_date': creation_date})
            if filename.endswith('_pdf.crypt'):
                file_path = os.path.join(pdf_report_path, filename)
                creation_time = os.path.getctime(file_path)
                creation_date = datetime1.utcfromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
                report_data.append({'name': filename, 'type': 'PDF', 'creation_date': creation_date})
            if filename.endswith('.xlsx'):
                file_path = os.path.join(xlsx_report_path, filename)
                creation_time = os.path.getctime(file_path)
                creation_date = datetime1.utcfromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
                report_data.append({'name': filename, 'type': 'Excel', 'creation_date': creation_date})
        grid_table.update()


    async def get_params():
        output_mode_query = tabs.value
        endpoint_value = None
        search_options = []
        search_values = []
        csv_output_query = csv_output.value
        pdf_output_query = pdf_output.value
        if teams_output_config == "True":
            teams_output_query = teams_output.value
        if email_output_config == "True":
            email_output_query = email_output.value
        if teams_output_config == "False":
            teams_output_query = False
        if email_output_config == "False":
            email_output_query = False
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
        snmp_device_input_query = snmp_device_input.value
        snmp_company_input_query = snmp_company_input.value
        snmp_hostname_input_query = snmp_hostname_input.value
        snmp_type_input_query = snmp_type_input.value
        tcp_device_input_query = tcp_device_input.value
        tcp_company_input_query = tcp_company_input.value
        tcp_deviceid_input_query = tcp_deviceid_input.value
        tcp_port_input_query = tcp_port_input.value
        http_device_input_query = http_device_input.value
        http_company_input_query = http_company_input.value
        http_url_input_query = http_url_input.value
        http_pattern_input_query = http_pattern_input.value

        if csv_output_query is False and pdf_output_query is False and email_output_query is True:
            ui.notify('You need to select either PDF or Excel Output to send by email', type='warning')
            return

        else:

            if output_mode_query == "agents":
                endpoint_value = devices_endpoint

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



            if output_mode_query == "snmp":
                endpoint_value = snmp_devices_endpoint
                if snmp_device_input_query != '':
                    search_options.append('Device Name')
                    search_values.append(snmp_device_input_query)
                if snmp_company_input_query != '':
                    search_options.append('Company')
                    search_values.append(snmp_company_input_query)
                if snmp_hostname_input_query != '':
                    search_options.append('Hostname')
                    search_values.append(snmp_hostname_input_query)
                if snmp_type_input_query != '':
                    search_options.append('Type')
                    search_values.append(snmp_type_input_query)

            if output_mode_query == "http":
                endpoint_value = http_devices_endpoint
                if http_device_input_query != '':
                    search_options.append('Device Name')
                    search_values.append(http_device_input_query)
                if http_company_input_query != '':
                    search_options.append('Company')
                    search_values.append(http_company_input_query)
                if http_url_input_query != '':
                    search_options.append('URL')
                    search_values.append(http_url_input_query)
                if http_pattern_input_query != '':
                    search_options.append('Pattern')
                    search_values.append(http_pattern_input_query)

            if output_mode_query == "tcp":
                endpoint_value = tcp_devices_endpoint
                if tcp_device_input_query != '':
                    search_options.append('Device Name')
                    search_values.append(tcp_device_input_query)
                if tcp_company_input_query != '':
                    search_options.append('Company')
                    search_values.append(tcp_company_input_query)
                if tcp_deviceid_input_query != '':
                    search_options.append('Device ID')
                    search_values.append(tcp_deviceid_input_query)
                if tcp_port_input_query != '':
                    search_options.append('Port')
                    search_values.append(tcp_port_input_query)

            if len(search_options) == 0 and len(search_values) == 0:
                ui.notify('Fields are empty', type='negative')
                return
            loading_spinner.set_visibility(True)
            wait_message.set_visibility(True)
            await asyncio.sleep(1)
            fetch_device_information(search_options, search_values, teams_output=teams_output_query,
                                     csv_output=csv_output_query, email_output=email_output_query,
                                     pdf_output=pdf_output_query, cli_mode=False,
                                     output_mode=output_mode_query, endpoint=endpoint_value)
            loading_spinner.visible = False
            wait_message.visible = False
            if output_mode_query == "agents":
                result_table.set_visibility(True)
                snmp_result_table.set_visibility(False)
                tcp_result_table.set_visibility(False)
                http_result_table.set_visibility(False)
                deletecheckbox.set_visibility(True)
            if output_mode_query == "snmp":
                snmp_result_table.set_visibility(True)
                result_table.set_visibility(False)
                tcp_result_table.set_visibility(False)
                http_result_table.set_visibility(False)
                deletecheckbox.set_visibility(True)

            if output_mode_query == "tcp":
                snmp_result_table.set_visibility(False)
                result_table.set_visibility(False)
                tcp_result_table.set_visibility(True)
                http_result_table.set_visibility(False)
                deletecheckbox.set_visibility(True)
            if output_mode_query == "http":
                snmp_result_table.set_visibility(False)
                result_table.set_visibility(False)
                tcp_result_table.set_visibility(False)
                http_result_table.set_visibility(True)
                deletecheckbox.set_visibility(True)


    def delete_cache_folder():
        cache_directory = f"{user_cache_folder}/{userlogin}"

        # Check if cache directory exists
        if os.path.exists(cache_directory):
            # Remove the cache directory and all its contents
            shutil.rmtree(cache_directory)
            ui.notify('Successfully flushed cached files', type='positive')
        else:
            ui.notify('No Cache Available', type='warning')

    def email_file_history(filepath):

        # Set up the email message
        msg = MIMEMultipart()
        msg['From'] = email_sender_var
        msg['To'] = email_recipient_var
        msg['Subject'] = email_subject_var
        attachment = MIMEApplication(open(filepath, 'rb').read())
        attachment.add_header('Content-Disposition', 'attachment', filename=filepath)
        msg.attach(attachment)



        # Add the body text to the email
        msg.attach(MIMEText(email_body_var, 'plain'))
        # Send the email
        context = sslmail.create_default_context(sslmail.Purpose.CLIENT_AUTH)
        context.verify_mode = sslmail.CERT_REQUIRED
        context.load_default_certs(sslmail.Purpose.SERVER_AUTH)

        try:
            if ssl_var:
                with smtplib.SMTP_SSL(smtp_server_var, smtp_port_var, context=context) as server:

                    server.ehlo()
                    server.login(smtp_username_var, smtp_password_var)
                    server.send_message(msg)
            elif tls_var:
                with smtplib.SMTP(smtp_server_var, smtp_port_var) as server:
                    server.ehlo()
                    server.starttls()
                    server.ehlo()
                    server.login(smtp_username_var, smtp_password_var)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(smtp_server_var, smtp_port_var) as server:
                    server.ehlo()
                    server.login(smtp_username_var, smtp_password_var)
                    server.send_message(msg)

            ui.notify(f"Email from {email_sender_var} sent successfully to {email_recipient_var}", type='positive')

        except smtplib.SMTPException as e:
            ui.notify({str(e)}, type='negative')





    async def delete_selected_rows_agent():
        agents_selected_rows = await result_table.get_selected_rows()
        snmp_selected_rows = await snmp_result_table.get_selected_rows()
        tcp_selected_rows = await tcp_result_table.get_selected_rows()
        http_selected_rows = await http_result_table.get_selected_rows()
        if agents_selected_rows:
            for row in agents_selected_rows:
                agentid = row['AgentID']
                agentid_str = str(agentid)
                atera_device_delete(devices_endpoint, agentid_str)
                ui.notify('Device deleted successfully', color='positive')

        if snmp_selected_rows:
            for row in snmp_selected_rows:
                deviceid = row['device_id']
                agentid_str = str(deviceid)
                atera_device_delete(snmp_devices_endpoint2, agentid_str)
                ui.notify('Device deleted successfully', color='positive')

        if tcp_selected_rows:
            for row in tcp_selected_rows:
                deviceid = row['device_id']
                agentid_str = str(deviceid)
                atera_device_delete(tcp_devices_endpoint2, agentid_str)
                ui.notify('Device deleted successfully', color='positive')

        if http_selected_rows:
            for row in http_selected_rows:
                deviceid = row['device_id']
                agentid_str = str(deviceid)
                atera_device_delete(http_devices_endpoint2, agentid_str)
                ui.notify('Device deleted successfully', color='positive')
        delete_cache_folder()


    def save_config(event=None):
        save_api_key = apikey.value
        username = app.storage.user.get('username')
        if save_api_key != "":

            encrypted_password = app.storage.user.get('encrypted_password')
            hashed_password = hashlib.sha256(encrypted_password.encode()).hexdigest()
            # Generate a key from the hashed password using PBKDF2

            stored_salt = get_salt(username)
            userbytes = bytes(userlogin, 'utf-8')
            tokenbytes = bytes(master_token, 'utf-8')
            saltbytes = bytes(stored_salt, 'utf-8')
            salt = userbytes + tokenbytes + saltbytes
            iterations = 100000  # Adjust the number of iterations to a suitable value
            key_length = 32  # Length of the desired key in bytes
            backend = default_backend()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=key_length,
                salt=salt,
                iterations=iterations,
                backend=backend
            )
            key = base64.urlsafe_b64encode(kdf.derive(hashed_password.encode()))
            # Create a Fernet cipher instance with the key
            cipher = Fernet(key)
            encrypted_api_key = cipher.encrypt(save_api_key.encode())
            set_api_key(username, encrypted_api_key)


        webhook_var = webhook.value
        geolocation_var = geolocation.value
        save_geoprovider = ip_api_url
        eol_var = oseol.value
        onlineonly_var = online_only.value
        excel_var = xlsx_export.value
        cache_var = cache_mode.value
        email_sender_var = emailsender.value
        email_recipient_var = emailrecipient.value
        email_subject_var = emailsubject.value
        email_body_var = emailbody.value
        smtp_server_var = smtpserver.value
        smtp_port_var = smtpport.value
        smtp_username_var = smtpusername.value
        smtp_port_var = smtppassword.value
        tls_var = starttls.value
        ssl_var = ssl.value

        update_user_config(userlogin, webhook_var, geolocation_var, save_geoprovider, eol_var,
                           onlineonly_var, excel_var, cache_var, smtp_server_var, smtp_port_var,
                           smtp_username_var, smtp_port_var, tls_var, ssl_var,
                           email_sender_var, email_recipient_var, email_subject_var, email_body_var)





        ui.open('/')

    globalconfig.read(global_config_file)
    teams_output_config = globalconfig['GENERAL']['teams']
    email_output_config = globalconfig['GENERAL']['email']
    cache_mode_config = globalconfig['GENERAL']['cachemode']
    forcecachemode = globalconfig['GENERAL']['forcecache']

    def logout_session():
        app.storage.user.clear()
        ui.open('/login')
    def change_password():
        ui.open('/security')

    with ui.header(elevated=True).style('background-color: #FF176B').classes('justify-center'):

        #ui.label('').classes('self-center').classes('order-2 font-black')
        ui.image(logo_img).classes('max-w-md self-center order-3')
        #ui.label('Atera Report Generator').classes('self-center').classes('order-3')
        ui.button(on_click=lambda: left_drawer.toggle(), icon='history').props('flat color=white').classes('order-1 self-center justify-end')
        ui.button(on_click=lambda: right_drawer.toggle(), icon='settings').props('flat color=white').classes('order-4 self-center justify-end')
    with ui.row().classes('items-center self-center'):
        ui.label(f'Account: {app.storage.user["nickname"]}').classes('text-2xl self-center')
    with ui.row().classes('items-center self-center'):
        ui.button('logout',on_click=logout_session, icon='logout').props('outline square color=pink-5')
        ui.button('Security',on_click=change_password, icon='security').props('outline square color=pink-5')
    with ui.row().classes('items-center self-center'):
        if app.storage.user.get('role') == 'admin':
            ui.button('Admin Console',on_click=lambda: (ui.open('/adminconsole')), icon='admin_panel_settings').props('outline square color=pink-5')
    with ui.right_drawer(fixed=False).style('').props('bordered overlay=True, behavior=mobile').classes('') as right_drawer:


        ui.label('General Options')
        with ui.splitter(horizontal=True) as splitter:
            with splitter.before:
                apikey = ui.input(label='Atera API Key', placeholder='ENCRYPTED', password=True,
                                        validation={'Input too long': lambda value: len(value) < 100}).classes('q-mb-md')
                ui.label('This field is empty if already set')
                if teams_output_config == "True":
                    webhook = ui.input(label='Webhook URL', placeholder='https://......',
                                        validation={'Input too long': lambda value: len(value) < 500}).bind_value(locals(), 'saved_webhook_option').classes('q-mb-md')
                ui.label('Advanced Report Options')
                with ui.row():
                    oseol = ui.checkbox('OS EOL').bind_value(locals(), 'eol_var')
                    geolocation = ui.checkbox('Geolocation').bind_value(locals(), 'geolocation_var')
                with ui.row():
                    online_only = ui.checkbox('Online Devices').bind_value(locals(), 'onlineonly_var')
                    xlsx_export = ui.checkbox('Excel File').bind_value(locals(), 'excel_var')
                if cache_mode_config == "True" and forcecachemode == "False":
                    with ui.row():
                        cache_mode = ui.checkbox('Cache Mode').bind_value(locals(), 'cache_var')

            with splitter.after:
                if email_output_config == "True":
                    ui.label('Email Options')
                    emailrecipient = ui.input(label='Email Recipient', placeholder='recipient@something.com',
                                  validation={'Input too long': lambda value: len(value) < 100}).bind_value(locals(), 'email_recipient_var').classes('q-mb-md')
                    emailsender = ui.input(label='Email Sender', placeholder='sender@something.com',
                                  validation={'Input too long': lambda value: len(value) < 100}).bind_value(locals(), 'email_sender_var').classes('q-mb-md')
                    emailsubject = ui.input(label='Email Subject', placeholder='Atera Report Results',
                                  validation={'Input too long': lambda value: len(value) < 100}).bind_value(locals(), 'email_subject_var').classes('q-mb-md')

                    emailbody = ui.textarea(label='Email Body', placeholder='Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt',validation={'Input too long': lambda value: len(value) < 100}).bind_value(locals(), 'email_body_var').classes('q-mb-md')
        with ui.splitter(horizontal=True) as splitter:
            with splitter.before:
                if email_output_config == "True":
                    smtpserver = ui.input(label='SMTP Server', placeholder='smtp.office365.com',validation={'Input too long': lambda value: len(value) < 100}).bind_value(locals(), 'smtp_server_var').classes('q-mb-md')
                    smtpport = ui.input(label='SMTP Port', placeholder='587',validation={'Input too long': lambda value: len(value) < 100}).bind_value(locals(), 'smtp_port_var').classes('q-mb-md')
                    with ui.row():


                        ssl = ui.checkbox('SSL').bind_value(locals(), 'ssl_var')
                        starttls = ui.checkbox('TLS').bind_value(locals(), 'tls_var')

                    smtpusername = ui.input(label='SMTP Username', placeholder='sender@something.com',validation={'Input too long': lambda value: len(value) < 100}).bind_value(locals(), 'smtp_username_var').classes('q-mb-md')
                    smtppassword = ui.input(label='SMTP Password', placeholder='Enter your Password Here', password=True,validation={'Input too long': lambda value: len(value) < 100}).bind_value(locals(), 'smtp_password_var').classes('q-mb-md')
                save_config_button = ui.button('Save Configuration', on_click=save_config, icon='save').classes('q-mt-md justify-center')
                if cache_mode_config == "True":
                    cache_flush = ui.button('Flush Cache', on_click=delete_cache_folder, icon='cached').classes('q-mt-md justify-center')

    csv_report_path = os.path.join(user_report_path, 'csv')
    pdf_report_path = os.path.join(user_report_path, 'pdf')
    xlsx_report_path = os.path.join(user_report_path, 'xlsx')
    csv_files = os.listdir(csv_report_path)
    pdf_files = os.listdir(pdf_report_path)
    xlsx_files = os.listdir(xlsx_report_path)
    all_files = csv_files + pdf_files + xlsx_files
    with ui.left_drawer(fixed=False).style('').props('bordered overlay=True, behavior=mobile width=400').classes('self-center').style('width:400') as left_drawer:
        report_data = []
        for filename in all_files:
            if filename.endswith('.csv'):
                file_path = os.path.join(csv_report_path, filename)
                creation_time = os.path.getctime(file_path)
                creation_date = datetime1.utcfromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
                report_data.append({'name': filename, 'type': 'CSV', 'creation_date': creation_date})
            if filename.endswith('_pdf.crypt'):
                file_path = os.path.join(pdf_report_path, filename)
                creation_time = os.path.getctime(file_path)
                creation_date = datetime1.utcfromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
                report_data.append({'name': filename, 'type': 'PDF', 'creation_date': creation_date})
            if filename.endswith('.xlsx'):
                file_path = os.path.join(xlsx_report_path, filename)
                creation_time = os.path.getctime(file_path)
                creation_date = datetime1.utcfromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
                report_data.append({'name': filename, 'type': 'Excel', 'creation_date': creation_date})

        def delete_file(filename):
            if filename.endswith('.csv'):
                deletefile = os.path.join(csv_report_path, filename)
            if filename.endswith('_pdf.crypt'):
                deletefile = os.path.join(pdf_report_path, filename)
            if filename.endswith('.xlsx'):
                deletefile = os.path.join(xlsx_report_path, filename)

            os.remove(deletefile)


        async def delete_selected_files():
            selected_rows = await grid_table.get_selected_rows()
            if selected_rows:
                for row in selected_rows:
                    filename = row['name']
                    delete_file(filename)
                ui.notify(f'{filename} deleted', color='positive')
                report_data.clear()
                csv_files = os.listdir(csv_report_path)
                pdf_files = os.listdir(pdf_report_path)
                xlsx_files = os.listdir(xlsx_report_path)
                all_files = csv_files + pdf_files + xlsx_files
                for filename in all_files:
                    if filename.endswith('.csv'):
                        file_path = os.path.join(csv_report_path, filename)
                        creation_time = os.path.getctime(file_path)
                        creation_date = datetime1.utcfromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
                        report_data.append({'name': filename, 'type': 'CSV', 'creation_date': creation_date})
                    if filename.endswith('_pdf.crypt'):
                        file_path = os.path.join(pdf_report_path, filename)
                        creation_time = os.path.getctime(file_path)
                        creation_date = datetime1.utcfromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
                        report_data.append({'name': filename, 'type': 'PDF', 'creation_date': creation_date})
                    if filename.endswith('.xlsx'):
                        file_path = os.path.join(xlsx_report_path, filename)
                        creation_time = os.path.getctime(file_path)
                        creation_date = datetime1.utcfromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
                        report_data.append({'name': filename, 'type': 'Excel', 'creation_date': creation_date})
                grid_table.update()
            else:
                ui.notify('No file selected.', color='warning')

        async def email_selected_files():
            selected_rows = await grid_table.get_selected_rows()
            if selected_rows:
                for row in selected_rows:
                    filename = row['name']
                    email_file_history(filename)

        async def download_row():
            selected_rows = await grid_table.get_selected_rows()
            if selected_rows:
                ipadd = get_ip()
                for row in selected_rows:
                    filename = row['name']
                    bufferSize = 128 * 1024
                    encrypted_password = app.storage.user.get('encrypted_password')
                    if filename.endswith('.csv'):
                        app.add_static_files(f'/reports/{userlogin}/csv', csv_report_path)
                        ui.download(f'http://{ipadd}:8080/reports/{userlogin}/csv/{filename}')
                        ui.timer(20.0, lambda: app.remove_route(f'/reports/{userlogin}/csv'), once=True)
                    if filename.endswith('.xlsx'):
                        app.add_static_files(f'/reports/{userlogin}/xlsx', xlsx_report_path)
                        ui.download(f'http://{ipadd}:8080/reports/{userlogin}/xlsx/{filename}')
                        ui.timer(20.0, lambda: app.remove_route(f'/reports/{userlogin}/xlsx'), once=True)

                    if filename.endswith('_pdf.crypt'):
                        decrypted_filename = os.path.splitext(filename)[0]
                        decrypted_filename = decrypted_filename + '.pdf'
                        encrypted_pdf_filename = os.path.join(pdf_path_download, f"{filename}")
                        decrypted_pdf_filename = os.path.join(pdf_path_download, f"{decrypted_filename}")

                        pyAesCrypt.decryptFile(encrypted_pdf_filename, decrypted_pdf_filename, encrypted_password, bufferSize)
                        app.add_static_files(f'/reports/{userlogin}/pdf', pdf_report_path)
                        ui.download(f'http://{ipadd}:8080/reports/{userlogin}/pdf/{decrypted_filename}')
                        ui.timer(10.0, lambda: app.remove_route(f'/reports/{userlogin}/pdf'), once=True)
                        ui.timer(10.0, lambda: os.remove(decrypted_pdf_filename), once=True)
                ui.notify(f'{filename} downloaded!', color='positive')
            else:
                ui.notify('No file selected.', color='warning')



        grid_table = ui.aggrid({
            'columnDefs': [
                {'headerName': 'Name', 'field': 'name', 'checkboxSelection': True, 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
                {'headerName': 'Type', 'field': 'type','width': 70, 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
                {'headerName': 'Date', 'field': 'creation_date','width': 140, 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            ],
            'rowData': report_data,
            'rowSelection': 'multiple',
            'defaultColDef': {'resizable': True},
        }).classes('max-h-200 self-center')
        with ui.column().classes('self-center'):
            ui.button('Delete selected reports', on_click=delete_selected_files, icon='delete').classes('q-mt-md self-center').props('color=red-5')
            ui.button('Download selected reports', on_click=download_row, icon='cloud_download').classes('q-mt-md self-center').props('color=green-5')
            ui.button('Email selected reports', on_click=email_selected_files, icon='mail').classes('q-mt-md self-center').props('color=green-5')








    with ui.tabs().classes('w-full') as tabs:
        one = ui.tab('agents', label='Agent Devices', icon='computer').classes('q-px-xl')
        two = ui.tab('snmp', label='SNMP Devices', icon='dns').classes('q-px-xl')
        three = ui.tab('tcp', label='TCP Devices', icon='lan').classes('q-px-xl')
        four = ui.tab('http', label='HTTP Devices', icon='language').classes('q-px-xl')

    with ui.tab_panels(tabs, value='agents').classes('self-center w-full') as panels:
        with ui.tab_panel(one):

            with ui.splitter().classes('self-center') as splitter:
                with splitter.before:
                    device_input = ui.input(label='Device Name', placeholder='Ex. TS-SRV-01',
                                            validation={'Input too long': lambda value: len(value) < 100}).classes('mr-2').on('keydown.enter', get_params)
                    company_input = ui.input(label='Customer', placeholder='Ex. Microsoft Corporation',
                                             validation={'Input too long': lambda value: len(value) < 100}).classes('mr-2').on('keydown.enter', get_params)
                    serialnumber_input = ui.input(label='Serial Number', placeholder='Ex. J7H3D4',
                                                  validation={'Input too long': lambda value: len(value) < 100}).classes('mr-2').on('keydown.enter', get_params)
                    lanip_input = ui.input(label='LAN IP', placeholder='Ex. 192.168.1.1',
                                           validation={'Input too long': lambda value: len(value) < 100}).classes('mr-2').on('keydown.enter', get_params)
                    ostype_input = ui.input(label='OS Type', placeholder='Ex. Server',
                                            validation={'Input too long': lambda value: len(value) < 100}).classes('mr-2').on('keydown.enter', get_params)
                    vendor_input = ui.input(label='Vendor', placeholder='Ex. Dell',
                                            validation={'Input too long': lambda value: len(value) < 100}).classes('mr-2').on('keydown.enter', get_params)

                with splitter.after:
                    username_input = ui.input(label='Username', placeholder='Ex. user1',
                                              validation={'Input too long': lambda value: len(value) < 100}).classes('ml-2').on('keydown.enter', get_params)
                    wanip_input = ui.input(label='WAN IP', placeholder='Ex. 1.1.1.1',
                                           validation={'Input too long': lambda value: len(value) < 100}).classes('ml-2').on('keydown.enter', get_params)
                    domainname_input = ui.input(label='Domain Name', placeholder='Ex. domain.local',
                                                validation={'Input too long': lambda value: len(value) < 100}).classes('ml-2').on('keydown.enter', get_params)
                    model_input = ui.input(label='Model', placeholder='Ex. Latitude 3520',
                                           validation={'Input too long': lambda value: len(value) < 100}).classes('ml-2').on('keydown.enter', get_params)
                    processor_input = ui.input(label='Processor', placeholder='Ex. i5',
                                               validation={'Input too long': lambda value: len(value) < 100}).classes('ml-2').on('keydown.enter', get_params)
                    #core_input = ui.input(label='Core Amount', placeholder='start typing',
                    #                      validation={'Input too long': lambda value: len(value) < 20}).classes('ml-2')
                    osversion_input = ui.input(label='Operating System', placeholder='Ex. Windows Server 2022',
                                               validation={'Input too long': lambda value: len(value) < 100}).classes('ml-2').on('keydown.enter', get_params)


        with ui.tab_panel(two):
            with ui.splitter().classes('self-center') as splitter:
                with splitter.before:
                    snmp_device_input = ui.input(label='Device Name', placeholder='Ex. Fortigate 60F',
                                            validation={'Input too long': lambda value: len(value) < 100}).classes('mr-2').on('keydown.enter', get_params)
                    snmp_company_input = ui.input(label='Customer', placeholder='Ex. Microsoft Corporation',
                                             validation={'Input too long': lambda value: len(value) < 100}).classes('mr-2').on('keydown.enter', get_params)

                with splitter.after:
                    snmp_hostname_input = ui.input(label='Hostname', placeholder='Ex. 192.168.1.1',
                                             validation={'Input too long': lambda value: len(value) < 100}).classes('ml-2').on('keydown.enter', get_params)
                    snmp_type_input = ui.input(label='Device Type', placeholder='Ex. Firewall',
                                             validation={'Input too long': lambda value: len(value) < 100}).classes('ml-2').on('keydown.enter', get_params)




        with ui.tab_panel(three):
            with ui.splitter().classes('self-center') as splitter:
                with splitter.before:
                    tcp_device_input = ui.input(label='Device Name', placeholder='Ex. Exterior Camera',
                                                 validation={'Input too long': lambda value: len(value) < 100}).classes(
                        'mr-2').on('keydown.enter', get_params)
                    tcp_company_input = ui.input(label='Customer', placeholder='Ex. Microsoft Corporation',
                                                  validation={'Input too long': lambda value: len(value) < 100}).classes(
                        'mr-2').on('keydown.enter', get_params)

                with splitter.after:
                    tcp_deviceid_input = ui.input(label='Device ID', placeholder='Ex. 111',
                                                   validation={'Input too long': lambda value: len(value) < 100}).classes('ml-2').on('keydown.enter', get_params)
                    tcp_port_input = ui.input(label='TCP Port', placeholder='Ex. 443',
                                               validation={'Input too long': lambda value: len(value) < 100}).classes('ml-2').on('keydown.enter', get_params)

        with ui.tab_panel(four):
            with ui.splitter().classes('self-center') as splitter:
                with splitter.before:
                    http_device_input = ui.input(label='Device Name', placeholder='Ex. Office Portal Login',
                                                validation={'Input too long': lambda value: len(value) < 100}).classes(
                        'mr-2').on('keydown.enter', get_params)
                    http_company_input = ui.input(label='Customer', placeholder='Ex. Microsoft Corporation',
                                                 validation={'Input too long': lambda value: len(value) < 100}).classes(
                        'mr-2').on('keydown.enter', get_params)

                with splitter.after:
                    http_url_input = ui.input(label='URL', placeholder='Ex. portal.office.com',
                                                  validation={'Input too long': lambda value: len(value) < 100}).classes('ml-2').on('keydown.enter', get_params)
                    http_pattern_input = ui.input(label='Pattern', placeholder='Ex. Sign in',
                                              validation={'Input too long': lambda value: len(value) < 100}).classes('ml-2').on('keydown.enter', get_params)
    with ui.grid(columns=4).classes('self-center'):
        csv_output = ui.switch('Excel').props('color=pink-5')
        pdf_output = ui.switch('PDF').props('color=pink-5')
        if teams_output_config == "True":
            teams_output = ui.switch('Teams').props('color=pink-5')
        if email_output_config == "True":
            email_output = ui.switch('Email').props('color=pink-5')


    ui.button('Generate Report', on_click=get_params, icon='cloud_download').props('color=pink-5').classes('self-center')
    loading_spinner = ui.spinner('Hourglass', size='xl', color='pink').classes('self-center')
    loading_spinner.visible = False
    wait_message = ui.label('Fetching device information from Atera...').classes('self-center')
    wait_message.visible = False
    result_table = ui.aggrid({
        'columnDefs': [
            {'headerName': 'ID', 'field': 'AgentID','width': 100, 'checkboxSelection': True},
            {'headerName': 'Name', 'field': 'device_name', 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'Customer', 'field': 'customer', 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'Domain', 'field': 'domain', 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'User', 'field': 'username', 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'OS', 'field': 'os', 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'EOL', 'field': 'eol','width': 140, 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'Type', 'field': 'type','width': 140, 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'Vendor', 'field': 'vendor','width': 140, 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'Model', 'field': 'device_model', 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'Serial#', 'field': 'serial', 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'Status', 'field': 'status','width': 120, 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'Last Reboot', 'field': 'device_lastreboot','filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'LAN IP', 'field': 'ip', 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'WAN IP', 'field': 'wanip', 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'Geolocation', 'field': 'geolocation', 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'ISP', 'field': 'isp', 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'CPU', 'field': 'cpu', 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'Free', 'field': 'c_drive_free_gb','width': 120, 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'Used', 'field': 'c_drive_used_gb','width': 120, 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'Total', 'field': 'c_drive_total_gb','width': 120, 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': '% Used', 'field': 'diskusage','width': 120,'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},




        ],
        'rowData': agents_data,
        'rowSelection': 'multiple',
        'defaultColDef': {'resizable': True},
    }).classes('max-h-300 self-center')
    result_table.visible = False

    snmp_result_table = ui.aggrid({
        'columnDefs': [
            {'headerName': 'Device ID', 'field': 'device_id', 'filter': 'agTextColumnFilter', 'floatingFilter': True,'sortable': "true", 'checkboxSelection': True},
            {'headerName': 'Name', 'field': 'device_name', 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'Customer', 'field': 'device_company', 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'Hostname', 'field': 'device_hostname', 'filter': 'agTextColumnFilter', 'floatingFilter': True,
             'sortable': "true"},
            {'headerName': 'Status', 'field': 'status', 'filter': 'agTextColumnFilter', 'floatingFilter': True,
             'sortable': "true"},
            {'headerName': 'Type', 'field': 'type', 'filter': 'agTextColumnFilter', 'floatingFilter': True,
             'sortable': "true"},
            {'headerName': 'Security', 'field': 'security', 'filter': 'agTextColumnFilter', 'floatingFilter': True,
             'sortable': "true"},

        ],
        'rowData': snmp_data,
        'rowSelection': 'multiple',
        'defaultColDef': {'resizable': True},
    }).classes('max-h-300 self-center')
    snmp_result_table.visible = False

    tcp_result_table = ui.aggrid({
        'columnDefs': [
            {'headerName': 'Device ID', 'field': 'device_id', 'filter': 'agTextColumnFilter', 'floatingFilter': True,
             'sortable': "true", 'checkboxSelection': True},
            {'headerName': 'Name', 'field': 'device_name', 'filter': 'agTextColumnFilter', 'floatingFilter': True,
             'sortable': "true"},
            {'headerName': 'Customer', 'field': 'device_company', 'filter': 'agTextColumnFilter',
             'floatingFilter': True, 'sortable': "true"},

            {'headerName': 'Status', 'field': 'status', 'filter': 'agTextColumnFilter', 'floatingFilter': True,
             'sortable': "true"},
            {'headerName': 'TCP Port', 'field': 'tcp_port', 'filter': 'agTextColumnFilter', 'floatingFilter': True,
             'sortable': "true"},

        ],
        'rowData': tcp_data,
        'rowSelection': 'multiple',
        'defaultColDef': {'resizable': True},
    }).classes('max-h-300 self-center')
    tcp_result_table.visible = False

    http_result_table = ui.aggrid({
        'columnDefs': [
            {'headerName': 'Device ID', 'field': 'device_id', 'filter': 'agTextColumnFilter', 'floatingFilter': True,
             'sortable': "true", 'checkboxSelection': True},
            {'headerName': 'Name', 'field': 'device_name', 'filter': 'agTextColumnFilter', 'floatingFilter': True,
             'sortable': "true"},
            {'headerName': 'Customer', 'field': 'device_company', 'filter': 'agTextColumnFilter',
             'floatingFilter': True, 'sortable': "true"},
            {'headerName': 'URL', 'field': 'device_url', 'filter': 'agTextColumnFilter',
             'floatingFilter': True,
             'sortable': "true"},
            {'headerName': 'Status', 'field': 'status', 'filter': 'agTextColumnFilter', 'floatingFilter': True,
             'sortable': "true"},
            {'headerName': 'Pattern', 'field': 'device_pattern', 'filter': 'agTextColumnFilter', 'floatingFilter': True,
             'sortable': "true"},
            {'headerName': 'Pattern Status', 'field': 'device_patternup', 'filter': 'agTextColumnFilter', 'floatingFilter': True,
             'sortable': "true"},

        ],
        'rowData': http_data,
        'rowSelection': 'multiple',
        'defaultColDef': {'resizable': True},
    }).classes('max-h-300 self-center')
    http_result_table.visible = False
    deletecheckbox = ui.checkbox('Delete Devices').classes('self-center').props('color=red-5')
    deletecheckbox.visible = False
    delete_button = ui.button('Confirm Deletion', on_click=delete_selected_rows_agent, icon='delete').props('color=red-5').classes('self-center').bind_visibility_from(deletecheckbox, 'value')
    delete_button.visible = False
    delete_button_text = ui.label('This action will delete the device from your atera console').classes('self-center').bind_visibility_from(deletecheckbox, 'value')
    delete_button_text.visible = False

@ui.page('/information')
def about() -> None:
    with ui.card().classes('absolute-center').style('background-color: #FF176B'):
        ui.image(login_img).classes('max-w-md self-center')
        ui.label('Security Informations').classes('self-center text-2xl').tailwind.text_color('white')
        ui.label('Is ARG safe to use?').classes('self-center text-xl').tailwind.text_color('white')
        ui.label("Your senstive information is confidential and encrypted through your login password. It cannot be retrieved by the operator of this service").classes('self-center')
        ui.label("Some Features such as geolocation requires to share the public IP of devices to a third party service. If you are not comfortable with this, please disable the feature.").classes('self-center')
        ui.label("No identifying information gets shared. It's like doing a what's my IP on google.").classes('self-center')
        ui.label("When you delete your account, every data related gets wiped from the service. Nothing stays").classes('self-center')
        
        ui.label('').classes('self-center text-lg').tailwind.text_color('white')
        ui.label('About the beta').classes('self-center text-2xl').tailwind.text_color('white')
        ui.label("As the software is in beta, major changes could happen in the meantime").classes('self-center')
        ui.label("").classes('self-center')



@ui.page('/login', dark = darkmode)
def login() -> None:
    globalconfig.read(global_config_file)
    registration = globalconfig['GENERAL']['registration']
    def try_login() -> None:
        username_value = username.value
        password_value = password.value
        otp_user_code = otp_entry.value
        hashed_password_encrypt = hashlib.sha3_384(password_value.encode()).hexdigest()
        hashed_username = hashlib.sha3_512(username_value.encode()).hexdigest()
        stored_tier, stored_nickname, stored_salt, stored_totp, stored_role, stored_password, match = verify_login(hashed_username)


        if match == True:
            hashed_password = hashlib.sha3_512((password_value + stored_salt).encode()).hexdigest()
            if stored_totp is not None:
                totpserver = pyotp.TOTP(stored_totp)
                servertotp = totpserver.now()
                if not servertotp == otp_user_code:
                    ui.notify('OTP Invalid', color='negative')
                    return

            if stored_password == hashed_password:

                app.storage.user.update(
                    {'username': hashed_username, 'authenticated': True, 'encrypted_password': hashed_password_encrypt, 'nickname': stored_nickname, 'tier': stored_tier, 'role': stored_role})
                ui.open('/')
                return
        ui.notify('Wrong username or password', color='negative')

    if app.storage.user.get('authenticated', False):
        return RedirectResponse('/')

    def create_login() -> None:
        ui.open('/create-login')

    with ui.card().classes('absolute-center').style('background-color: #FF176B'):
        ui.image(login_img).classes('max-w-md self-center')
        ui.label('Public Beta').classes('self-center text-lg').tailwind.text_color('white')
        ui.label('User Login').classes('self-center text-2xl').tailwind.text_color('white')
        username = ui.input('Username').props('color=grey-1').on('keydown.enter', try_login).classes('self-center w-full')
        password = ui.input('Password', password=True, password_toggle_button=True).props('color=grey-1').on('keydown.enter', try_login).classes('self-center w-full')
        otp_entry = ui.input('OTP').props('color=grey-1').classes('self-center w-full')
        ui.button('Login', on_click=try_login, icon='login').props('color=green-5').classes('self-center')

        def handle_key(e: KeyEventArguments):
            if e.key == 'enter' and not e.action.repeat:
                create_login()

        keyboard = ui.keyboard(on_key=handle_key)
        if registration == "True":
            ui.button('User Registration', on_click=create_login, icon='create').props('color=orange-5').classes('self-center')

@ui.page('/security', dark=darkmode)


def change_password_page() -> None:
    if not app.storage.user.get('authenticated', False):
        return RedirectResponse('/login')
    userlogin = app.storage.user["username"]
    user_report_path = os.path.join(report_path, f'{userlogin}')
    globalconfig.read(global_config_file)
    def logout_session():
        app.storage.user.clear()
        ui.open('/login')

    def newtotp() -> None:
        otp = newotpcode
        update_totp(userlogin, otp)
        logout_session()
    def delete_account() -> None:

        if deletecheck.value == True:
            role = app.storage.user.get('role')
            if role == "user":
                delete_user(userlogin)
                delete_user_config(userlogin)
                user_cache_directory = f"{user_cache_folder}/{userlogin}"
                if os.path.exists(user_cache_directory):
                    # Remove the cache directory and all its contents
                    shutil.rmtree(user_cache_directory)
                user_report_directory = user_report_path
                if os.path.exists(user_report_directory):
                    # Remove the cache directory and all its contents
                    shutil.rmtree(user_report_directory)
                logout_session()
            if role == "admin":
                ui.notify('Only another admin can delete an admin account', color='negative')
        if deletecheck.value == False:
            ui.notify('Please confirm before clicking on delete account', color='warning')

    def change_password() -> None:
        new_password = new_password_input.value
        try:
            delete_api_key(userlogin)
        except FileNotFoundError:
            print(f"API Key does not exist. Skipping deletion.")
        if len(new_password) < 8:
            ui.notify('Password must be at least 8 characters long', color='negative')
            return
        salt = secrets.token_hex(16)
        hashed_password = hashlib.sha3_512((new_password + salt).encode()).hexdigest()
        update_password(userlogin,hashed_password)
        update_salt(userlogin, salt)
        ui.notify('Password changed successfully', color='positive')
        logout_session()
    def main_page() -> None:
        ui.open('/')
    with ui.card().classes('absolute-center').style('background-color: #FF176B'):
        ui.image(login_img).classes('max-w-md self-center')

        with ui.column().classes('self-center q-mb-md'):
            ui.label('Password Change').classes('self-center text-2xl outline square q-pa-sm').tailwind.text_color('white')
            new_password_input = ui.input('New Password', password=True, password_toggle_button=True).props('color=grey-1').classes('self-center w-full')
            ui.label('Minimum requirement of 8 characters').classes('self-center').tailwind.text_color('white')
            ui.label('You will get disconnected after the change').classes('self-center').tailwind.text_color('white')
            ui.label('The API Key will be wiped from your config').classes('self-center').tailwind.text_color('white')
            ui.button('Change Password', on_click=change_password, icon='create').props('color=green-5').classes('self-center')
        with ui.column().classes('self-center q-mb-md'):
            ui.label('Change or Enable OTP').classes('self-center text-2xl outline square q-pa-sm').tailwind.text_color('white')
            newotpcode = pyotp.random_base32()
            ui.label(f'OTP: {newotpcode}').classes('self-center q-pa-xs').tailwind.text_color('white')
            ui.button('Save OTP', on_click=newtotp, icon='create').props('color=green-5').classes('self-center')
            ui.label('input this code in your authenticator app').classes('self-center').tailwind.text_color('white')
            ui.label('It will be required during login').classes('self-center').tailwind.text_color('white')
        with ui.column().classes('self-center q-mb-md'):
            ui.label('Account Deletion').classes('self-center text-2xl outline square q-pa-sm').tailwind.text_color('white')
            deletecheck = ui.checkbox('Confirmation').classes('self-center')
            ui.button('Delete Account', on_click=delete_account, icon='delete').props('color=red-5').classes('self-center')
            ui.label('Deleting an account is permanent. All Data will be lost').classes('self-center').tailwind.text_color('white')

        ui.button('Back to ARG', on_click=main_page, icon='reply').props('color=amber-5').classes('self-center')

@ui.page('/create-login', dark=darkmode)
def create_login_page() -> None:
    globalconfig.read(global_config_file)
    registration = globalconfig['GENERAL']['registration']
    def create_login() -> None:
        new_username = new_username_input.value
        new_password = new_password_input.value
        new_nickname = new_nickname_input.value
        new_role = "user"
        new_tier = "free"
        new_otp = newotpcode
        salt = secrets.token_hex(16)
        hashed_username = hashlib.sha3_512(new_username.encode()).hexdigest()
        hashed_password = hashlib.sha3_512((new_password + salt).encode()).hexdigest()
        if new_username == "":
            ui.notify('Username missing', color='negative')
            return
        if new_nickname == "":
            ui.notify('Nickname missing', color='negative')
            return
        if new_nickname == new_password:
            ui.notify('Nickname cannot be the same value as the password', color='negative')
            return
        if new_nickname == new_username:
            ui.notify('Nickname cannot be the same value as the username', color='negative')
            return
        if new_username == new_password:
            ui.notify('username cannot be the same value as the password', color='negative')
        if len(new_password) < 8:
            ui.notify('Password must be at least 8 characters long', color='negative')
            return
        new_user(hashed_username, hashed_password, new_nickname, salt, new_otp, new_tier, new_role)

        ui.notify('Login created successfully', color='positive')
        ui.open('/login')
    def login_page() -> None:
        ui.open('/login')
    with ui.card().classes('absolute-center').style('background-color: #FF176B'):
        ui.image(login_img).classes('max-w-md self-center')
        newotpcode = pyotp.random_base32()
        if registration == "True":
            ui.label('Public Beta').classes('self-center text-lg').tailwind.text_color('white')
            ui.label('User Registration').classes('self-center text-2xl').tailwind.text_color('white')

            new_username_input = ui.input('Username').props('color=grey-1').classes('self-center w-full')
            new_password_input = ui.input('Password', password=True, password_toggle_button=True).props('color=grey-1').classes('self-center w-full')
            new_nickname_input = ui.input('Nickname').props('color=grey-1').classes('self-center w-full')
            ui.label(f'OTP: {newotpcode}').classes('self-center outline square q-pa-xs').tailwind.text_color('white')
            ui.label('Password minimum requirement of 8 characters').classes('self-center').tailwind.text_color('white')
            ui.label('MFA is currently required to create an account').classes('self-center').tailwind.text_color('white')
            ui.label('Enter this code in Microsoft Authenticator or any compatible app').classes('self-center').tailwind.text_color('white')
            ui.button('Create', on_click=create_login, icon='create').props('color=green-5').classes('self-center')
        if registration == "False":
            ui.label('User Registration is currently disabled').classes('self-center').tailwind.text_color('white')
        ui.button('Back', on_click=login_page, icon='reply').props('color=red-5').classes('self-center')


@ui.page('/adminconsole', dark=darkmode)
def adminconsole() -> None:
    globalconfig.read(global_config_file)
    if app.storage.user.get('role') != 'admin':
        return RedirectResponse('/')
    userlogin = app.storage.user["username"]
    usernickname = app.storage.user["nickname"]
    users_data = []
    user_data = get_role_user_tier()


    for data in user_data:
        nickname = data[0]
        role = data[1]
        tier = data[2]
        users_data.append({'name': nickname, 'type': role, 'tier': tier})

    def change_password(username1):
        new_password = change_password_input.value
        real_username = get_username_by_nickname(username1)
        delete_api_key(real_username)
        if len(new_password) < 8:
            ui.notify('Password must be at least 8 characters long', color='negative')
            return
        salt = secrets.token_hex(16)
        hashed_password = hashlib.sha3_512((new_password + salt).encode()).hexdigest()
        update_password(real_username,hashed_password)
        update_salt(real_username, salt)
        ui.notify('Password changed successfully', color='positive')



    def delete_cache_folder():
        # Check if cache directory exists
        if os.path.exists(cachepath):
            # Remove the cache directory and all its contents
            shutil.rmtree(cachepath)
            ui.notify('Successfully flushed all cached files', type='positive')
        else:
            ui.notify('No Cache Available', type='warning')


    def delete_user_cache(username1):
        real_username = get_username_by_nickname(username1)
        user_cache_directory = f"{user_cache_folder}/{real_username}"
        if os.path.exists(user_cache_directory):
            # Remove the cache directory and all its contents
            shutil.rmtree(user_cache_directory)


    def delete_user_report_folder(username1):
        real_username = get_username_by_nickname(username1)
        user_report_directory = f"{report_path}/{real_username}"
        if os.path.exists(user_report_directory):
            # Remove the cache directory and all its contents
            shutil.rmtree(user_report_directory)

    def save_general_config():
        save_registration = registration_checkbox.value
        save_cachemode = cachemode_checkbox.value
        save_teams = teams_checkbox.value
        save_email = email_checkbox.value
        save_forcecachemode = forcecachemode_checkbox.value
        save_darkmode = darkmode_checkbox.value

        globalconfig['GENERAL'] = {
            'registration': save_registration,
            'cachemode': save_cachemode,
            'teams': save_teams,
            'email': save_email,
            'forcecache':save_forcecachemode,
            'darkmode': save_darkmode

        }
        with open(f'server/global_configs/globalconfig.ini', 'w') as global_config_file:
            globalconfig.write(global_config_file)
        ui.notify('Configuration Saved', color='positive')

    def create_login() -> None:
        new_username = new_username_input.value
        new_password = new_password_input.value
        new_nickname = new_nickname_input.value
        new_type = new_type_input.value
        new_tier = new_tier_input.value
        salt = secrets.token_hex(16)
        hashed_username = hashlib.sha3_512(new_username.encode()).hexdigest()
        hashed_password = hashlib.sha3_512((new_password + salt).encode()).hexdigest()

        if new_username == "":
            ui.notify('Username missing', color='negative')
            return
        if new_nickname == "":
            ui.notify('Nickname missing', color='negative')
        if new_nickname == new_password:
            ui.notify('Nickname cannot be the same value as the password', color='negative')
            return
        if new_nickname == new_username:
            ui.notify('Nickname cannot be the same value as the username', color='negative')
            return
        if new_username == new_password:
            ui.notify('username cannot be the same value as the password', color='negative')
        if len(new_password) < 8:
            ui.notify('Password must be at least 8 characters long', color='negative')
            return
        new_user(hashed_username, hashed_password, new_nickname, salt, None, new_tier, new_type)

        ui.notify('Account created successfully', color='positive')


        users_data.clear()
        user_data = get_role_user_tier()

        for data in user_data:
            nickname = data[0]
            role = data[1]
            tier = data[2]
            users_data.append({'name': nickname, 'type': role, 'tier': tier})
        grid_users.update()



    def generate_totp():
        newotpcode = pyotp.random_base32()
        return newotpcode

    def software() -> None:
        ui.open('/')
    with ui.card().classes('absolute-center').style('background-color: #FF176B'):
        ui.image(login_img).classes('max-w-md self-center')
        ui.label('Admin Console').classes('self-center text-2xl').tailwind.text_color('white')
        ui.label(f'Account: {app.storage.user["nickname"]}').classes('text-xl self-center').tailwind.text_color('white')
        ui.button('Logout',on_click=lambda: (app.storage.user.clear(), ui.open('/login')), icon='logout').props('color=red-5').classes('self-center')
        ui.button('Launch ARG', on_click=software, icon='login').classes('q-mt-md self-center').props('color=green-5')
        ui.button('Global Settings',on_click=lambda: left_drawer.toggle(), icon='settings').props('flat color=white').classes('self-center')
        ui.button('User Management',on_click=lambda: right_drawer.toggle(), icon='manage_accounts').props('flat color=white').classes('self-center')
    with ui.right_drawer(fixed=False).style('background-color: #FF176B').props('bordered overlay=True').classes('self-center').style('width:400') as right_drawer:
        with ui.column().classes('self-center'):
            ui.label('User Management').classes('self-center text-2xl').tailwind.text_color('white')
            ui.label('Account Creation').classes('self-center text-lg').tailwind.text_color('white')
            new_username_input = ui.input('Username').props('color=grey-1 clearable').classes('self-center w-full')
            new_password_input = ui.input('Password', password=True, password_toggle_button=True).props('color=grey-1 clearable').classes('self-center w-full')
            new_nickname_input = ui.input('Nickname').props('color=grey-1 clearable').classes('self-center w-full')
            new_type_input = ui.select(['admin', 'user'], value='user').classes('self-center w-full')
            new_tier_input = ui.select(['free', 'basic', 'unlimited'], value='free').classes('self-center w-full')
            ui.label('Password requirement of 8 characters').classes('self-center').tailwind.text_color('white')
            ui.button('Create Account', on_click=create_login, icon='create').props('color=green-5').classes('self-center')
            ui.label('User Account Management').classes('self-center text-lg').tailwind.text_color('white')


        async def delete_selected_rows_users():
            selected_rows = await grid_users.get_selected_rows()
            if selected_rows:
                for row in selected_rows:
                    username1 = row['name']
                    real_username = get_username_by_nickname(username1)
                    hashed_username_verification = hashlib.sha3_512(userlogin.encode()).hexdigest()
                    if hashed_username_verification == real_username:
                        ui.notify('You cannot delete your own account', color='warning')
                        return
                    #SQL PUSH
                    delete_user_config(real_username)
                    delete_user(real_username)
                    #FILE PUSH
                    delete_user_cache(username1)
                    delete_user_report_folder(username1)


                users_data.clear()
                user_data = get_role_user_tier()

                for data in user_data:
                    nickname = data[0]
                    role = data[1]
                    tier = data[2]
                    users_data.append({'name': nickname, 'type': role, 'tier': tier})
                grid_users.update()

                ui.notify('Users deleted successfully. Please refresh the page.', color='positive')

            else:
                ui.notify('No user selected.', color='warning')
        async def delete_selected_rows_user_config():
            selected_rows = await grid_users.get_selected_rows()
            if selected_rows:
                for row in selected_rows:
                    username = row['name']
                    real_username = get_username_by_nickname(username)
                    delete_user_config(real_username)
                ui.notify('Users configuration deleted successfully', color='positive')
            else:
                ui.notify('No user selected.', color='warning')
        async def delete_selected_rows_totp():
            selected_rows = await grid_users.get_selected_rows()
            if selected_rows:
                for row in selected_rows:
                    username = row['name']
                    real_username = get_username_by_nickname(username)
                    delete_totp(real_username)
                ui.notify('TOTP deleted successfully', color='positive')
            else:
                ui.notify('No user selected.', color='warning')
        async def change_password_row():
            selected_rows = await grid_users.get_selected_rows()
            if selected_rows:
                for row in selected_rows:
                    username = row['name']
                    change_password(username)
                ui.notify('Password changed successfully', color='positive')
            else:
                ui.notify('No user selected.', color='warning')



        async def delete_selected_rows_user_cache():
            selected_rows = await grid_users.get_selected_rows()
            if selected_rows:
                for row in selected_rows:
                    username = row['name']
                    delete_user_cache(username)
                ui.notify('Users cache deleted successfully', color='positive')
            else:
                ui.notify('No user selected.', color='warning')
        async def delete_selected_rows_user_reports():
            selected_rows = await grid_users.get_selected_rows()
            if selected_rows:
                for row in selected_rows:
                    username = row['name']
                    delete_user_report_folder(username)
                ui.notify('Users reports deleted successfully', color='positive')
            else:
                ui.notify('No user selected.', color='warning')
        async def update_user_info():
            selected_rows = await grid_users.get_selected_rows()
            if selected_rows:
                new_tier = change_tier_input.value
                new_role = change_type_input.value
                for row in selected_rows:
                    username = row['name']
                    real_username = get_username_by_nickname(username)
                    update_tier(real_username, new_tier)
                    update_role(real_username, new_role)
                ui.notify('User role/tier updated', color='positive')
                users_data.clear()
                user_data = get_role_user_tier()

                for data in user_data:
                    nickname = data[0]
                    role = data[1]
                    tier = data[2]
                    users_data.append({'name': nickname, 'type': role, 'tier': tier})
                grid_users.update()


            else:
                ui.notify('No user selected.', color='warning')


        grid_users = ui.aggrid({
            'columnDefs': [
                {'headerName': 'Name', 'field': 'name', 'checkboxSelection': True, 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
                {'headerName': 'Type', 'field': 'type', 'filter': 'agTextColumnFilter', 'floatingFilter': True, 'sortable': "true"},
                {'headerName': 'Tier', 'field': 'tier', 'filter': 'agTextColumnFilter', 'floatingFilter': True,'sortable': "true"},
            ],
            'rowData': users_data,
            'rowSelection': 'multiple',
            'defaultColDef': {'resizable': True},
        }).classes('max-h-40')
        with ui.column().classes('self-center'):
            ui.label('Role').classes('self-center text-md').tailwind.text_color('white')
            change_type_input = ui.select(['admin', 'user'], value='user').classes('self-center w-full')
            ui.label('Customer Tier').classes('self-center text-md').tailwind.text_color('white')
            change_tier_input = ui.select(['free', 'basic', 'unlimited'], value='unlimited').classes('self-center w-full')
            ui.button('Update user role/tier', on_click=update_user_info, icon='change_circle').classes('q-mt-md self-center').props('color=green-5')
            change_password_input = ui.input('New Password', password=True, password_toggle_button=True).props('color=grey-1 clearable').classes('self-center w-full')
            ui.button('Change Password', on_click=change_password_row, icon='change_circle').classes('q-mt-md self-center').props('color=green-5')
            ui.button('Delete User account', on_click=delete_selected_rows_users, icon='delete').classes('q-mt-md self-center').props('color=red-5')
            ui.button('Flush User Settings', on_click=delete_selected_rows_user_config, icon='settings').classes('q-mt-md self-center').props('color=orange-5')
            ui.button('Flush User reports', on_click=delete_selected_rows_user_reports, icon='folder').classes('q-mt-md self-center').props('color=orange-5')
            ui.button('Flush User cache', on_click=delete_selected_rows_user_cache, icon='cached').classes('q-mt-md self-center').props('color=orange-5')
            ui.button('Remove TOTP', on_click=delete_selected_rows_totp, icon='history').classes('q-mt-md self-center').props('color=orange-5')


    with ui.left_drawer(fixed=False).style('background-color: #FF176B').props('bordered overlay=True').classes('self-center') as left_drawer:
        with ui.column().classes('self-center'):
            ui.label('Global Settings').classes('self-center text-2xl').tailwind.text_color('white')
            registration_state = globalconfig['GENERAL']['registration']
            registration_var = registration_state.lower() == 'true'
            cache_state = globalconfig['GENERAL']['cachemode']
            cache_var = cache_state.lower() == 'true'
            teams_state = globalconfig['GENERAL']['teams']
            teams_var = teams_state.lower() == 'true'
            email_state = globalconfig['GENERAL']['email']
            email_var = email_state.lower() == 'true'
            force_cache_state = globalconfig['GENERAL']['forcecache']
            force_cache_var = force_cache_state.lower() == 'true'
            dark_mode_state = globalconfig['GENERAL']['darkmode']
            dark_mode_var = dark_mode_state.lower() == 'true'
            ui.label('Option visibility').classes('self-center text-lg').tailwind.text_color('white')
            registration_checkbox = ui.checkbox('Enable User Registration').bind_value(locals(), 'registration_var').classes('self-center')
            teams_checkbox = ui.checkbox('Enable Teams Output').bind_value(locals(), 'teams_var').classes('self-center')
            email_checkbox = ui.checkbox('Enable Email Output').bind_value(locals(), 'email_var').classes('self-center')
            ui.label('Parameters').classes('self-center text-lg').tailwind.text_color('white')
            cachemode_checkbox = ui.checkbox('Enable Cache Mode').bind_value(locals(), 'cache_var').classes('self-center')
            forcecachemode_checkbox = ui.checkbox('Force Cache Mode').bind_value(locals(), 'force_cache_var').classes('self-center')
            ui.label('UI').classes('self-center text-lg').tailwind.text_color('white')
            darkmode_checkbox = ui.checkbox('Dark Mode (reboot required)').bind_value(locals(), 'dark_mode_var').classes('self-center')
            save_config_button = ui.button('Save Configuration', on_click=save_general_config, icon='save').classes('self-center').props('color=green-5')
            ui.label('Maintenance').classes('self-center text-2xl').tailwind.text_color('white')
            cache_flush = ui.button('Global Cache Flush', on_click=delete_cache_folder, icon='cached').classes('q-mt-md self-center').props('color=red-5')
            profile_flush = ui.button('Graceful Shutdown', on_click=app.shutdown,icon='power_settings_new').classes('self-center').props('color=red-5')

icon = 'data:image/png;base64,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'
#ui.run(title='Atera Report Generator', host='0.0.0.0',port=4543,ssl_keyfile=key,ssl_certfile=certificate, favicon=icon, reload=False, storage_secret=master_token)
ui.run(title='Atera Report Generator', host='0.0.0.0', favicon=icon, reload=False, storage_secret=master_token)
import warnings

def fxn():
    warnings.warn("deprecated", DeprecationWarning)

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    fxn()
