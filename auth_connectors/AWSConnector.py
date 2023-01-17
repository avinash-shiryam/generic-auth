#FIXME -> change the location of utils before running the class
from app.utils import exception_utils

from utils.local_utils import exampleAuthFunction
from time import perf_counter
import logging as log

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