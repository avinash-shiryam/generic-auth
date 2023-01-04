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
        if kwargs:
            self.t1_start = perf_counter()
            if "AUTHORIZATION" in request.headers or "auth_token" in request.view_args:
                self.parse_headers(*args,**kwargs)
        else:
            raise exception_utils.NoAuthTokenPresentError

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

    def parse_headers(self,*args,**kwargs):
        self.token = request.headers.get('AUTHORIZATION') or request.view_args.get('auth_token')
        if self.token:
            try:
                self.headers = jwt.get_unverified_headers(self.token)
                self.kid = self.headers['kid']
                self.keys = self.fetch_public_key()
                self.public_key_aws = self.check_and_fetch_kid(kid=self.kid, keys=self.keys)
                # construct the public key
                self.public_key = jwk.construct(self.public_key_aws)
                # retrieve payload and signature
                self.message, self.encoded_signature = str(self.token).rsplit('.', 1)
                # decode the signature
                self.decoded_signature = base64url_decode(self.encoded_signature.encode('utf-8'))
                # verify the signature

                #move to next stage
                self.validate_auth(*args,**kwargs)
            except:
                print("some random ass error")

    def validate_auth(self,*args,**kwargs):
        try:
            if not self.public_key.verify(self.message.encode("utf8"), self.decoded_signature):
                # Signature verification failed
                logging.info("signature verification failed")
                raise exception_utils.UserUnauthorizedError(message="Authentication failed")
            claims = jwt.get_unverified_claims(self.token)
            if time.time() > claims['exp']:
                # Token is expired
                return user_utils.response_dict(status=400, message="Signature expired, login again")
            iss = claims['iss']
            iss = iss[iss.rfind("/") + 1:]
            if iss != ConfigVariable.COGNITO_USER_POOL_ID:
                logging.info("issuer mismatch")
                # Issuer claim mismatch
                raise exception_utils.UserUnauthorizedError(message="Authentication failed")
            self.sub = claims.get("sub")
            role = []
            if claims.get("cognito:roles"):
                for data in claims.get("cognito:roles"):
                    data = data.split(":")
                    data = data[-1].split("/")
                    role.append(data[-1])
            self.group_names = claims.get("cognito:groups", [])

            # move to next stage
            if ConfigVariable.IS_SECURE:
                self.check_source(*args,**kwargs)
        except:
            return exception_utils.UserUnauthorizedError(message="multiple sessions not allowed")

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
    
