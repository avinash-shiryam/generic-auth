from abc import ABC,abstractclassmethod, ABCMeta
import firebase_admin
from firebase_admin import credentials
from firebase_admin import auth
from firebase_admin.auth import Client
from firebase_admin import firestore
from config import ConfigVariable
from flask import request
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
from jwt import ExpiredSignatureError
from time import perf_counter
from datetime import datetime
from app.models.user import user
from local_utils import google_client
from constants import CONSTANT_GROUPNAME
from utils import exception_utils, user_utils
from utils.user_utils import response_dict
from config import ConfigVariable
from flask import request,g
from jose import jwk,jwt
from jose.utils import base64url_decode

google_cred = credentials.Certificate(cert=ConfigVariable.GCP_SECRET)
google_default_app = firebase_admin.initialize_app(google_cred)
google_client = Client(app=google_default_app)




class exampleAuthFunction(ABC):

    # __init__ will be inferenced from here, no need to declare it in the derived classes (AWSAuth, FirebaseAuth)
    def __init__(self,*args,**kwargs):
        self.executor_function(*args,**kwargs)
    
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

    @abstractclassmethod
    def executor_function(self,*args,**kwargs):
        self.parse_headers(*args,**kwargs)
        self.validate_auth(*args,**kwargs)
        self.check_source_truth(*args,**kwargs)

    @abstractclassmethod
    def parse_headers(self,*args,**kwargs):

        if "AUTHORIZATION" in request.headers or "auth_token" in request.view_args:
            self.auth_token = request.headers.get('AUTHORIZATION') or request.view_args.get('auth_token')
            return self.auth_token

    @abstractclassmethod
    def validate_auth(self,*args,**kwargs):

        def aws(self,*args,**kwargs):
            try:
                # Signature verification Successful. Retrieve claims and verify
                claims = jwt.get_unverified_claims(self.auth_token)
                self.validate_claims(claims)
                self.sub = claims.get("sub")
                self.group_names = claims.get("cognito:groups", [])
            except:
                raise exception_utils.NotAllowedError

        def firebase(self,*args,**kwargs):
            if self.auth_token:
                    try:
                        decoded_token = google_client.verify_id_token(self.auth_token)
                        kwargs['user_sub'] = decoded_token.get('sub')
                        kwargs['email'] = decoded_token.get('email')
                        kwargs['firebase_phone'] = decoded_token.get("phone_number")

                        self.payload = jwt.decode(self.auth_token, os.getenv("SECRET_KEY"), algorithms="HS256")
                    except ExpiredSignatureError:
                        return response_dict(status=401, data=None, message="Signature expired, login again")
                    except Exception as e:
                        return response_dict(status=401, data=None, message="jwt decode error: %s" % str(e))
            else:
                return response_dict(status=401, data=None, message="No Authorization")
        
        def custom(self,*args,**kwargs):
            user_sub = self.payload["user_sub"]
            # FIXME: will be used in future, fow now disabled.
            # auth_token_info_cache = redis_utils.get(key=user_sub)
            # auth_token_cache = auth_token_info_cache.get(requester_ip)

            # if auth_token_cache != token:
            #    log.info("request from ip: %s" % requester_ip)
            #    return response_dict(status=401, data=None, message="Multiple login, please logout first")

            kwargs['user_sub'] = user_sub
            kwargs['user_type'] = self.payload.get('user_type')
            firebase_user_obj = google_client.get_user(user_sub)
            kwargs['email'] = firebase_user_obj.email

            if self.payload.get('user_type') == "candidate":
                user_type_obj = Candidate()
            elif self.payload.get('user_type') == "employer":
                user_type_obj = Employer()
            elif self.payload.get('user_type') == "operation":
                user_type_obj = Operation()
            else:
                return response_dict(status=500, data=None, message="Invalid user type")

        if(kwargs.get("type")=="validate_auth-aws"): 
            aws(self)
        elif(kwargs.get("type")=="validate_auth-firebase"):
            firebase(self)
        elif(kwargs.get("type")=="validate_auth-customauth"):
            custom(self)

    @abstractclassmethod
    def check_source_truth(self,*args,**kwargs):
        
        """
        Independent functions for AWS, Firebase
        """

        def aws(self,*args,**kwargs):
            try:
                # Multi session feature
                self.check_multi_login_feature(self.auth_token, self.group_names, self.sub)
                self.user_obj = user.User.fetch_by_provided_data(params={"user_sub": self.sub})
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
            except:
                raise exception_utils.NoAuthTokenPresentError

        def firebase(self,*args,**kwargs):
            self.user_sub = self.payload.get("user_sub")
            kwargs['user_sub'] = self.user_sub
            kwargs['email'] = firebase_user_obj.email
            firebase_user_obj = google_client.get_user(self.user_sub)
            # assumed firebase_user_obj.email carries a unique_user_id
            unique_user_id = (firebase_user_obj.email).get("unique_user_id")

            #Considering genericness, assumed a single user type
            user_obj = user()

            if unique_user_id:
                filter_params = {"user_type": self.payload.get('user_type'), 'unique_user_id': unique_user_id}
                user_obj.update(
                    filter_params=filter_params,
                    update_params={'last_accessed': datetime.now(pytz.utc).strftime("%Y-%m-%d %H:%M:%S")},
                )
            try:
                return response_dict(status=201, data=None, message="Source of Truth verification successful")
            except Exception as e:
                bugsnag.notify(e)
                return response_dict(status=500, data=None, message="Internal Server Error")

        if(kwargs.get("type")=="checksource-aws"): 
            aws(self)
        elif(kwargs.get("type")=="checksource-firebase"):
            firebase(self)
        