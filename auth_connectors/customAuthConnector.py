#FIXME add location of response_dict before instantsiation the class
from app.utils.user_utils import response_dict

import os
import jwt
from flask import request
from jwt import ExpiredSignatureError
from utils.local_utils import exampleAuthFunction

class customAuthVerification(exampleAuthFunction):
    
    def __init__(self,*args,**kwargs):
        super.executor_function(*args,**kwargs)
        
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
