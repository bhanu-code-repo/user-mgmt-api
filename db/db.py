# db/db.py
from pymongo import MongoClient
from config import MONGO_URI

class MongoDB:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(MongoDB, cls).__new__(cls)
            cls._instance.client = MongoClient(MONGO_URI)
            cls._instance.db = cls._instance.client["user_management_db"]
        return cls._instance

    def get_db(self):
        return self.db
