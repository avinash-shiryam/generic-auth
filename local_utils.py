from abc import ABC,abstractclassmethod
import firebase_admin
from firebase_admin import credentials
from firebase_admin import auth
from firebase_admin.auth import Client
from firebase_admin import firestore
from config import ConfigVariable

google_cred = credentials.Certificate(cert=ConfigVariable.GCP_SECRET)
google_default_app = firebase_admin.initialize_app(google_cred)
google_client = Client(app=google_default_app)




class exampleAuthFunction(ABC):
    
    # __init__ will be inferenced from here, no need to declare it in the derived classes (AWSAuth, FirebaseAuth)
    def __init__(self,*args,**kwargs):
        self.executor_function(*args,**kwargs)

    @abstractclassmethod
    def executor_function(self,*args,**kwargs):
        self.parse_headers(*args,**kwargs)
        self.validate_auth(*args,**kwargs)
        self.check_source_truth(*args,**kwargs)

    @abstractclassmethod
    def parse_headers(self,*args,**kwargs):
        pass

    @abstractclassmethod
    def validate_auth(self,*args,**kwargs):
        pass

    @abstractclassmethod
    def check_source_truth(self,*args,**kwargs):
        pass