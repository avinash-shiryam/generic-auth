#FIXME -> change the location of utils before running the class
from app.utils import exception_utils

from utils.local_utils import exampleAuthFunction
from time import perf_counter
import logging as log

class AWSAuth(exampleAuthFunction):

    def __init__(self,*args,**kwargs):
        self.t1_start = perf_counter()
        super.executor_function(*args,**kwargs)

    
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