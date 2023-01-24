import firebase_admin
from firebase_admin import credentials, auth, firestore
from flask import request, g
import os


"""
    Config class, which contains common required items 
"""

# format = {"user_sub":{"id":"000","user_name":"name","user_details":"details"}}
local_mock_db = {
    "007": {"id": "001", "user_name": "James Bond", "user_details": "On a mission"},
    "1221": {"id": "002", "user_name": "John Doe", "user_details": "Eating food"},
    "420": {"id": "003", "user_name": "Salmon Boi", "user_details": "sleeping soundly"},
}
            
# mock existing token dictionary
local_nium_token_dict = {"user_sub" : "as892as", "value" : {"date" : "00/00/0000", "auth_token" : "asdadasas23123", "metadata" : "some_group"}}

# google client constants
gcp_secret = os.getenv("gcp_secret")
google_cred = credentials.Certificate(cert=gcp_secret)
google_default_app = firebase_admin.initialize_app(google_cred)
google_client = auth.Client(app=google_default_app)
