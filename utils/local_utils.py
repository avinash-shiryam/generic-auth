from abc import ABC,abstractmethod, ABCMeta
import firebase_admin
from firebase_admin import credentials
from firebase_admin import auth
from firebase_admin.auth import Client
from firebase_admin import firestore
from flask import request,g
from Engine.config import ConfigVariable
import os

#google client constants
gcp_secret = os.getenv("gcp_secret")
google_cred = credentials.Certificate(cert=gcp_secret)
google_default_app = firebase_admin.initialize_app(google_cred)
google_client = Client(app=google_default_app)




class BaseAuthClass(ABC):

    """
        This abstract base class will be inherited by the auth_connectors to inherit basic functionality
    """

    # __init__ will be inferenced from here, no need to declare it in the derived classes (AWSAuth, FirebaseAuth)
    def __init__(self,*args,**kwargs):
        self.executor_function(*args,**kwargs)

    @abstractmethod
    def executor_function(self,*args,**kwargs):
        """
            1.Function takes care of executing the below functions serially
            2. Child classes can directly run this function using "super.executor_function()"
        """
        self.parse_headers()
        self.validate_auth()
        self.check_source_truth()

    @abstractmethod
    def parse_headers(self,*args,**kwargs):

        """
            BaseClass function for returning auth_token, functionality common for most auth connectors
        """

        if "AUTHORIZATION" in request.headers or "auth_token" in request.view_args:
            auth_token = request.headers.get('AUTHORIZATION') or request.view_args.get('auth_token')
            return auth_token

    @abstractmethod
    def validate_auth(self,*args,**kwargs):


        pass

    @abstractmethod
    def check_source_truth(self,*args,**kwargs):
        
        pass