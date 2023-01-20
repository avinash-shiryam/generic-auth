import json
import jwt
import logging
import time
from time import perf_counter
from flask import g
from jose import jwk, jwt
from jose.utils import base64url_decode
from datetime import datetime
from utils import exception_utils
from utils.local_utils import BaseAuthClass
from Engine.models.user import user
from Engine.config import ConfigVariable

#format = {"user_sub":{"id":"000","user_name":"name","user_details":"details"}}
local_mock_db = {
        "007": {"id":"001","user_name":"James Bond", "user_details": "On a mission"},
        "1221": {"id":"002","user_name":"John Doe", "user_details": "Eating food"},
        "420": {"id":"003","user_name":"Salmon Boi", "user_details": "sleeping soundly"},
        }


class AWSAuth(BaseAuthClass):

    """
    AWSAuth function takes care of the authentication pipeline using AWS
    """

    def __init__(self, *args, **kwargs):

        # None initialisations
        self.auth_token = None
        self.public_key = None
        self.message = None
        self.decoded_signature = None
        self.sub = None
        self.group_names = None

        self.t1_start = perf_counter()
        super().executor_function(*args, **kwargs)

    def get_contents(self, token):
        """
        Returns the message, public_key and decoded_signature in validate_cognito_jwt and validate_global_request
        """
        headers = jwt.get_unverified_headers(token)
        kid = headers["kid"]
        keys = self.fetch_public_key()
        public_key_aws = self.check_and_fetch_kid(kid=kid, keys=keys)
        # construct the public key
        public_key = jwk.construct(public_key_aws)
        # retrieve payload and signature
        message, encoded_signature = str(token).rsplit(".", 1)
        # decode the signature
        decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))
        return message, public_key, decoded_signature

    def _check_session_validity(self, current_token, user_sub, groups):
        """
        Check the session validity based on user sub
        """

        existing_token = ConfigVariable.NIUM_ACCESS_TOKEN_DICT.get(user_sub)
        if existing_token:
            existing_token = json.loads(existing_token.decode("utf-8"))
            existing_token = existing_token.get("auth_token")
        # update cache if no such data exists for the user
        if not existing_token:
            ConfigVariable.NIUM_ACCESS_TOKEN_DICT.set(
                name=user_sub,
                value=json.dumps(
                    {
                        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "auth_token": current_token,
                        "meta_data": groups,
                    }
                ),
                ex=3600,
            )
            return True
        # should not allow access with some other valid auth token
        if current_token != existing_token:
            return False
        return True

    def validate_claims(self, claims):
        """
        Validates claims
        """
        if time.time() > claims["exp"]:
            # Token is expired
            raise exception_utils.ParameterError(
                message="Signature expired, login again"
            )
        iss = claims.get("iss")
        iss = iss[iss.rfind("/") + 1 :]
        if iss != ConfigVariable.COGNITO_USER_POOL_ID:
            logging.info("issuer mismatch")
            # Issuer claim mismatch
            raise exception_utils.UserUnauthorizedError(message="Authentication failed")

    def check_multi_login_feature(self, token, group_names, sub):
        """
        Multi Login feature check and invoke
        Multi session feature support enable or disable as per env
        """
        if ConfigVariable.IS_SECURE:
            if self._check_session_validity(
                current_token=token, user_sub=sub, groups=group_names
            ):
                raise exception_utils.UserUnauthorizedError(
                    message="multiple sessions not allowed"
                )

    def parse_headers(self, *args, **kwargs):
        """
        Parses header files from the receiving container
        """
        self.auth_token = super().parse_headers()
        if self.auth_token:
            self.message, self.public_key, self.decoded_signature = self.get_contents(
                self.auth_token
            )

    def validate_auth(self, *args, **kwargs):
        """
        Checks if the data dump received form the point of origin are valid or not
        """
        try:
            if not self.public_key.verify(
                self.message.encode("utf8"), self.decoded_signature
            ):
                # Signature verification failed
                logging.info("signature verification failed")
                raise exception_utils.UserUnauthorizedError(
                    message="Authentication failed"
                )
            # Signature verification Successful. Retrieve claims and verify
            claims = jwt.get_unverified_claims(self.auth_token)
            self.validate_claims(claims)
            self.sub = claims.get("sub")
            self.group_names = claims.get("cognito:groups", [])
            # Multi session feature
            self.check_multi_login_feature(self.auth_token, self.group_names, self.sub)

            t1_stop = perf_counter()
            logging.info(
                "Elapsed time for cognito decorator in seconds: %s",
                t1_stop - self.t1_start,
            )
        except:
            raise exception_utils.NoAuthTokenPresentError

    def check_source_truth(self, *args, **kwargs):

        """
        Note. The check_source_truth functionality must be implemented by the dev themselves.
        """
        pass
