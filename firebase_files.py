import firebase_admin
from firebase_admin import credentials
from firebase_admin import auth
from firebase_admin.auth import Client
from firebase_admin import firestore
from config import ConfigVariable

google_cred = credentials.Certificate(cert=ConfigVariable.GCP_SECRET)
google_default_app = firebase_admin.initialize_app(google_cred)
google_client = Client(app=google_default_app)