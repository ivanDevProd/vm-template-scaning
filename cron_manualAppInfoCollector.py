import requests
import os
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import Error
import logging

# Load the .env file
load_dotenv()

logging.basicConfig(level=logging.INFO)

# DB parameters
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_HOST = os.getenv("MYSQL_HOST")

# DB config
mysql_config = {
    'user': 'root',
    'password': MYSQL_PASSWORD,
    'host': MYSQL_HOST,
    'database': 'vm_template_scan',
    'port': '3306'
}

