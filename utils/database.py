from pymongo import MongoClient
from utils.config import DATABASE_URI

# Establish a connection to the MongoDB database
client = MongoClient(DATABASE_URI)
db = client.assignment_portal
