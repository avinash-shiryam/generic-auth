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
        self.executor_function()
    
    def fetch_public_key(refresh_cache=False):
        """
        Fetch fetch_public_key from aws endpoint.
        """
        keys = None
        if not refresh_cache:
            public_keys = ConfigVariable.NIUM_ACCESS_TOKEN_DICT.get("public_key")
            if public_keys:
                keys = json.loads(public_keys)
        if not keys:
            response = requests.get(ConfigVariable.COGNITO_KEYS_URL)
            keys = json.loads(response.text)['keys']
            ConfigVariable.NIUM_ACCESS_TOKEN_DICT.set("public_key", json.dumps(keys), ex=3600)
        return keys
    
    def check_and_fetch_kid(self,kid, keys):
        """
        Check and fetch key id
        """
        key_index = [key for key in keys if key.get("kid") == kid]
        # Couldn't find Public key with matching kid
        if not key_index:
            # Refresh cache and check public key
            keys = self.fetch_public_key(refresh_cache=True)
            key_index = self.check_and_fetch_kid(kid=kid, keys=keys)
            if key_index:
                return key_index[0]
            logging.info("public key not found")
            raise exception_utils.UserUnauthorizedError(message="Authentication failed")
        return key_index[0]

    def _check_session_validity(current_token, user_sub, groups):
        """
        Check the session validity based on user sub
        """
        from datetime import datetime
        existing_token = ConfigVariable.NIUM_ACCESS_TOKEN_DICT.get(user_sub)
        if existing_token:
            existing_token = json.loads(existing_token.decode('utf-8'))
            existing_token = existing_token.get("auth_token")
        # update cache if no such data exists for the user
        if not existing_token:
            ConfigVariable.NIUM_ACCESS_TOKEN_DICT.set(
                name=user_sub,
                value=json.dumps({'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                'auth_token': current_token,
                                'meta_data': groups
                                }),
                ex=3600
            )
            return True
        # should not allow access with some other valid auth token
        if current_token != existing_token:
            return False
        return True

    def executor_function(status_token,*args,**kwargs):
        pass

    def parse_headers(self,*args,**kwargs):
        pass

    def validate_auth(self,*args,**kwargs):
        pass

    def check_source(self,*args,**kwargs):
        if CONSTANT_GROUPNAME not in self.group_names and  not self._check_session_validity(current_token=self.token, user_sub=self.sub, groups=self.group_names):
            return exception_utils.UserUnauthorizedError(message="multiple sessions not allowed")
        if CONSTANT_GROUPNAME not in self.group_names:
            user_obj = user.User.fetch_by_provided_data(params={"user_sub": self.sub})
            if not user_obj:
                logging.info("no user")
                raise exception_utils.UserUnauthorizedError(message="Authentication failed")
            kwargs["id"] = user_obj.id
            kwargs["user_sub"] = user_obj.user_sub
            kwargs["email_id"] = user_obj.email_id
            g.user_id = user_obj.id
        elif CONSTANT_GROUPNAME in self.group_names:
            user_obj = user.User.fetch_by_provided_data(params={"user_sub": self.sub})
            if user_obj:
                kwargs["id"] = user_obj.id
                kwargs["user_sub"] = user_obj.user_sub
                kwargs["email_id"] = user_obj.email_id
                g.user_id = user_obj.id
            else:
                g.user_id = -1
        kwargs["group_names"] = self.group_names
        kwargs["role_name"] = self.role
        self.t1_stop = perf_counter()
        logging.info("Elapsed time for cognito decorator in seconds: %s", self.t1_stop - self.t1_start)
    
