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
from datetime import datetime
from time import perf_counter
import time
class AWSAuth:

    def __init__(self,*args,**kwargs):
        self.t1_start = perf_counter()
        self.executor_dict = {"init":self.parse_headers,"headers_pass": self.validate_auth_and_check_source }
        self.executor_function(status_token="init",*args,**kwargs)

    def executor_function(self,status_token,*args,**kwargs):
        """
        Executor function takes care of sending the flow to next stage
        """
        if status_token is "header_fail" or "auth_fail":
            return f"procedure failed with error {status_token}"
        elif status_token == "finished":
            return "executed"
        else:
            self.executor_dict[status_token](*args,**kwargs)

    def get_contents(self,token):
        """
        Returns the message, public_key and decoded_signature in validate_cognito_jwt and validate_global_request
        """
        headers = jwt.get_unverified_headers(token)
        kid = headers['kid']
        keys = self.fetch_public_key()
        public_key_aws = self.check_and_fetch_kid(kid=kid, keys=keys)
        # construct the public key
        public_key = jwk.construct(public_key_aws)
        # retrieve payload and signature
        message, encoded_signature = str(token).rsplit('.', 1)
        # decode the signature
        decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
        return message, public_key, decoded_signature
    
    def _check_session_validity(self,current_token, user_sub, groups):
        """
        Check the session validity based on user sub
        """

        existing_token = ConfigVariable.NIUM_ACCESS_TOKEN_DICT.get(user_sub)
        if existing_token:
            existing_token = json.loads(existing_token.decode('utf-8'))
            existing_token = existing_token.get("auth_token")
        # update cache if no such data exists for the user
        if not existing_token:
            ConfigVariable.NIUM_ACCESS_TOKEN_DICT.set(
                name=user_sub,
                value=json.dumps({'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                'auth_token': current_token, 'meta_data': groups}),
                ex=3600,
            )
            return True
        # should not allow access with some other valid auth token
        if current_token != existing_token:
            return False
        return True
    
    def validate_claims(self,claims):
        """
        Validates claims
        """
        if time.time() > claims['exp']:
            # Token is expired
            raise exception_utils.ParameterError(message="Signature expired, login again")
        iss = claims.get("iss")
        iss = iss[iss.rfind("/") + 1:]
        if iss != ConfigVariable.COGNITO_USER_POOL_ID:
            logging.info("issuer mismatch")
            # Issuer claim mismatch
            raise exception_utils.UserUnauthorizedError(message="Authentication failed")
    
    def check_multi_login_feature(self,token, group_names, sub):
        """
        Multi Login feature check and invoke
        Multi session feature support enable or disable as per env
        """
        if ConfigVariable.IS_SECURE:
            if CONSTANT_GROUPNAME not in group_names and not self._check_session_validity(
                    current_token=token, user_sub=sub, groups=group_names
            ):
                raise exception_utils.UserUnauthorizedError(message="multiple sessions not allowed")

    def parse_headers(self,*args,**kwargs):
        try:
            if "AUTHORIZATION" in request.headers or "auth_token" in request.view_args:
                self.token = request.headers.get('AUTHORIZATION') or request.view_args.get('auth_token')
                message, public_key, decoded_signature = self.get_contents(self.token)
                # verify the signature
                if not public_key.verify(message.encode("utf8"), decoded_signature):
                    # Signature verification failed
                    logging.info("signature verification failed")
                    #return to executor_function as failed
                    self.executor_function(status_token="header_fail")
                    raise exception_utils.UserUnauthorizedError(message="Authentication failed")

                else:
                    #return to executor_function as passed
                    self.executor_function(status_token="header_pass")
                    
        except:
            pass

    def validate_auth_and_check_source(self,*args,**kwargs):
        # Signature verification Successful. Retrieve claims and verify
        claims = jwt.get_unverified_claims(self.token)
        self.validate_claims(claims)
        sub = claims.get("sub")
        self.group_names = claims.get("cognito:groups", [])
        # Multi session feature
        self.check_multi_login_feature(self.token, self.group_names, sub)
        self.user_obj = user.User.fetch_by_provided_data(params={"user_sub": sub})
        if CONSTANT_GROUPNAME not in self.group_names:
            if not self.user_obj:
                logging.info("no user")
                raise exception_utils.UserUnauthorizedError(message="Authentication failed")
            kwargs["id"] = self.user_obj.id
            kwargs["user_sub"] = self.user_obj.user_sub
            kwargs["email_id"] = self.user_obj.email_id
            g.user_id = self.user_obj.id
        else:
            if self.user_obj:
                kwargs["id"] = self.user_obj.id
                kwargs["user_sub"] = self.user_obj.user_sub
                kwargs["email_id"] = self.user_obj.email_id
                g.user_id = self.user_obj.id
            else:
                g.user_id = -1
        kwargs["group_names"] = self.group_names
        t1_stop = perf_counter()
        logging.info("Elapsed time for cognito decorator in seconds: %s", t1_stop - self.t1_start)
        return self.executor_function(status_token="finished")
    executor_function(status_token="auth_fail")
    raise exception_utils.NoAuthTokenPresentError
    
        
