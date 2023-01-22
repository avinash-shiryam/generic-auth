# FIXME add location of response_dict before instantsiation the class
import os
import jwt
import logging
import bugsnag
from flask import request
from datetime import datetime
import pytz
from jwt import ExpiredSignatureError
from Engine.models.user import user
from utils.local_utils import BaseAuthClass
from utils.local_utils import google_client
from utils.user_utils import response_dict
from decorator import decorator

#format = {"user_sub":{"id":"000","user_email":"some@soem.com","user_name":"name","user_details":"details"}}
local_mock_db = {
        "007": {"id":"001","user_email":"jamesbond@missionfail.com","user_name":"James Bond", "user_details": "On a mission"},
        "1221": {"id":"002","user_email":"johndoe@example.com","user_name":"John Doe", "user_details": "Eating food"},
        "420": {"id":"003","user_email":"salmonboi@deerkill.com","user_name":"Salmon Boi", "user_details": "sleeping soundly"},
        }
@decorator
class CustomAuth(BaseAuthClass):
    """
    pass
    """
    def __init__(self,func, *args, **kwargs):
        self.auth_token = None
        self.type_ = None
        self.payload = None
        super().executor_function(func,*args, **kwargs)

    def parse_headers(self, *args, **kwargs):
        self.auth_token = super().parse_headers()
        if self.auth_token:
            token_info = self.auth_token.split(" ")
            self.type_ = token_info[0]
            self.auth_token = token_info[1]
        else:
            return response_dict(
                status=401, data=None, message="Incorrect auth token type"
            )

    def validate_auth(self, *args, **kwargs):

        """
        Note.
        1. The secret key to decode the token must be passed in as an environment variable.
        """

        if self.type_ != "Bearer":
            return response_dict(
                status=401, data=None, message="Invalid auth token type"
            )
        try:
            self.payload = jwt.decode(
                self.auth_token, os.getenv("SECRET_KEY"), algorithms="HS256"
            )
        except ExpiredSignatureError:
            return response_dict(
                status=401, data=None, message="Signature expired, login again"
            )
        except Exception as e:
            return response_dict(
                status=401, data=None, message="jwt decode error: %s" % str(e)
            )

    def check_source_truth(self, *args, **kwargs):
        try:
            user_sub = self.payload["user_sub"]
            kwargs["user_sub"] = user_sub


            if local_mock_db.get(user_sub):
                # active entry is the dataset of the current user_sub on whose behalf an authz request has been received
                active_entry = local_mock_db.get(user_sub)
                kwargs["id"] = active_entry.get("id")
                kwargs["user_email"] = active_entry.get("user_email")
                kwargs["user_name"] = active_entry.get("user_name")
                kwargs["user_details"] = active_entry.get("user_details")

                logging.info("Authz request received and data as follows %s %s %s %s",kwargs["id"],kwargs["user_email"],kwargs["user_name"],kwargs["user_details"])


            return kwargs

        except:
            return response_dict(
                status=401, data=None, message="Error at source of truth"
            )
