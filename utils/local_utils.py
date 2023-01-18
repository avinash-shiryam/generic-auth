import requests
import json
import logging
import time
import functools
import jwt
import bugsnag
import pytz
import os
import logging as log
from abc import ABC,abstractmethod, ABCMeta
import firebase_admin
from firebase_admin import credentials
from firebase_admin import auth
from firebase_admin.auth import Client
from firebase_admin import firestore
from flask import request
from jwt import ExpiredSignatureError
from time import perf_counter
from datetime import datetime
from utils.local_utils import google_client
from flask import request,g
from jose import jwk,jwt
from jose.utils import base64url_decode

#FIXME fix these imports before instantsiating the exampleClass
from config import ConfigVariable
from app.models.user import user
from constants import CONSTANT_GROUPNAME
from app.utils.user_utils import response_dict
from config import ConfigVariable
from utils import exception_utils, user_utils

google_cred = credentials.Certificate(cert=ConfigVariable.GCP_SECRET)
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