from flask import request,g
from jose import jwk,jwt
from jose.utils import base64url_decode
import requests
import json
import logging
from config import ConfigVariable
from utils import exception_utils, user_utils
from constants import CONSTANT_GROUPNAME
from app.models.user import user
from time import perf_counter
import time
class AWSAuth:

    def __init__(self,*args,**kwargs):
        self.t1_start = perf_counter()
        self.executor_dict = {}
        self.executor_function(status_token="init",*args,**kwargs)

    def executor_function(status_token,*args,**kwargs):
        pass

    def parse_headers(self,*args,**kwargs):
        pass

    def validate_auth(self,*args,**kwargs):
        pass
        

    def check_source(self,*args,**kwargs):
        pass
        
