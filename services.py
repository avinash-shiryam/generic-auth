import jwt
import os
import logging as log
from flask import request,g
from jwt import ExpiredSignatureError
from utils import exception_utils, user_utils
from utils.user_utils import response_dict
from config import ConfigVariable

from local_utils import exampleAuthFunction

class AWSAuth(exampleAuthFunction):

    def __init__(self,*args,**kwargs):
        self.t1_start = perf_counter()
        self.executor_function(*args,**kwargs)

    def executor_function(self,*args,**kwargs):
        """
        Executor function takes care of sending the flow to next stage
        """
        self.parse_headers(*args,**kwargs)
        self.validate_auth(*args,**kwargs)
        self.check_source_truth(*args,**kwargs)


    def parse_headers(self,*args,**kwargs):
        self.auth_token = super.parse_headers()
        if self.auth_token:
            message, public_key, decoded_signature = self.get_contents(self.auth_token)
            # verify the signature
            if not public_key.verify(message.encode("utf8"), decoded_signature):
                # Signature verification failed
                log.info("signature verification failed")
                #return to executor_function as failed
                self.executor_function(status_token="header_fail")
                raise exception_utils.UserUnauthorizedError(message="Authentication failed")

    def validate_auth(self,*args,**kwargs):
        super.validate_auth(type="validate_auth-aws")
        
    
    def check_source_truth(self,*args,**kwargs):
        super.validate_auth(type="checksource-aws")


class FirebaseAuth(exampleAuthFunction):
    
    def __init__(self,*args,**kwargs):
        self.executor_function(*args,**kwargs)

    def executor_function(self,*args,**kwargs):
        self.parse_headers(*args,**kwargs)
        self.validate_auth(*args,**kwargs)
        self.check_source_truth(*args,**kwargs)

    def parse_headers(self,*args,**kwargs):
        self.auth_token = super.parse_headers()
        if self.auth_token:
                token_info = self.auth_token.split(" ")
                type_ = token_info[0]
                if type_ != "Bearer":
                    return response_dict(status=401, data=None, message="Invalid auth token type")
                self.auth_token = token_info[1]
            
        else:
            return response_dict(status=401, data=None, message="Incorrect auth token type")

    def validate_auth(self,*args,**kwargs):
        super.validate_auth(type="validate_auth-firebase")

    def check_source_truth(self,*args,**kwargs):
        super.check_source_truth(type="checksource-firebase")
    



class customAuthVerification(exampleAuthFunction):
    
    def __init__(self,*args,**kwargs):
        self.executor_function(*args,**kwargs)

    def executor_function(self,*args,**kwargs):
        self.parse_headers(*args,**kwargs)
        self.validate_auth(*args,**kwargs)
        self.check_source_truth(*args,**kwargs)

    def parse_headers(self,*args,**kwargs):
        super.parse_headers(type="parseheaders-customauth")
        if "AUTHORIZATION" in request.headers:
            token = request.headers["AUTHORIZATION"]
            token_info = token.split(" ")
            type_ = token_info[0]
            if type_ != "Bearer":
                return response_dict(status=401, data=None, message="Invalid auth token type")
            auth_token = token_info[1]
            if auth_token:
                try:
                    self.payload = jwt.decode(auth_token, os.getenv("SECRET_KEY"), algorithms="HS256")
                except ExpiredSignatureError:
                    return response_dict(status=401, data=None, message="Signature expired, login again")
                except Exception as e:
                    return response_dict(status=401, data=None, message="jwt decode error: %s" % str(e))

    def validate_auth(self,*args,**kwargs):
        super.validate_auth(type="validate_auth-customauth")

    def check_source_truth(self,*args,**kwargs):
        super.check_source_truth(type="checksource-customauth")

    
            
    
        
