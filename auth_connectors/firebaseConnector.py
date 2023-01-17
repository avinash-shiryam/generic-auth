#FIXME add location of response_dict before instantsiation the class
from app.utils.user_utils import response_dict

from utils.local_utils import exampleAuthFunction

class FirebaseAuth(exampleAuthFunction):
    
    def __init__(self,*args,**kwargs):
        self.executor_function(*args,**kwargs)

    def executor_function(self,*args,**kwargs):
        self.parse_headers(self)
        self.validate_auth(self)
        self.check_source_truth(self)

    def parse_headers(self,*args,**kwargs):
        self.auth_token = super.parse_headers()
        if self.auth_token:
                token_info = self.auth_token.split(" ")
                type_ = token_info[0]
                if type_ != "Bearer":
                    return response_dict(status=401, data=None, message="Invalid auth token type")
                self.auth_token = token_info[1]
            
        else:
            return response_dict(status=401, data=None, message="Incorrect auth token type")

    def validate_auth(self,*args,**kwargs):
        super.validate_auth(type="validate_auth-firebase")

    def check_source_truth(self,*args,**kwargs):
        super.check_source_truth(type="checksource-firebase")