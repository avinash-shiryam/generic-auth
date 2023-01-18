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


class CustomAuth(BaseAuthClass):
    def __init__(self, *args, **kwargs):
        self.auth_token = None
        self.type_ = None
        self.payload = None
        super().executor_function(*args, **kwargs)

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
        1. the secret key must be an environment variable
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

            # FIXME: will be used in future, for now disabled.
            # auth_token_info_cache = redis_utils.get(key=user_sub)
            # auth_token_cache = auth_token_info_cache.get(requester_ip)

            # if auth_token_cache != token:
            #    log.info("request from ip: %s" % requester_ip)
            #    return response_dict(status=401, data=None, message="Multiple login, please logout first")

            kwargs["user_sub"] = user_sub

            firebase_user_obj = google_client.get_user(user_sub)
            kwargs["email"] = firebase_user_obj.email

            # FIXME : usertype object
            user_type_obj = user.User()

            user_details = user_type_obj.fetch_by_email(firebase_user_obj.email)
            if user_details:

                unique_user_id = user_details.get("unique_user_id")

                kwargs["unique_user_id"] = unique_user_id
                kwargs["sub_user_type"] = user_details.get("sub_user_type")

                if unique_user_id:
                    filter_params = {
                        "user_type": self.payload.get("user_type"),
                        "unique_user_id": unique_user_id,
                    }
                    user_type_obj.update(
                        filter_params=filter_params,
                        update_params={
                            "last_accessed": datetime.now(pytz.utc).strftime(
                                "%Y-%m-%d %H:%M:%S"
                            )
                        },
                    )

        except:
            return response_dict(
                status=401, data=None, message="Error at source of truth"
            )
