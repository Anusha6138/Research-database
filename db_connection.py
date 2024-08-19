from dotenv import load_dotenv
import os
from pymongo import MongoClient
import urllib.parse

def get_mongo_connection():
    dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
    load_dotenv(dotenv_path)

    password = os.environ.get("MONGODB_PWD")
    e_username = urllib.parse.quote_plus("anusha-diptyangshu")
    e_password = urllib.parse.quote_plus(password)
    connection_string = f"mongodb+srv://{e_username}:anu-dip@anushadiptyangshu.plma7ch.mongodb.net/"
    #connection_string = "mongodb+srv://anusha-diptyangshu:anu-dip@anushadiptyangshu.plma7ch.mongodb.net/?retryWrites=true&w=majority&appName=AnushaDiptyangshu"

    try:
        # client = MongoClient(connection_string)
        #client = MongoClient('mongodb://106.51.8.242:27017/')
        client = MongoClient(connection_string)
        db = client.ResearchDatabase
        return db
    except Exception as e:
        print("Error connecting to MongoDB:", e)
        return None