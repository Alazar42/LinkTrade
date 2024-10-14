from pymongo import MongoClient

import os
from dotenv import load_dotenv
load_dotenv()

try:
    client = MongoClient(str(os.getenv("DATABASE_URL")))
    db = client["LinkTrade"]
    print("MongoDB connection successful!")
except Exception as e:
    print(f"An error occurred: {e}")
