"""
Authentication and Authorisation adapter module
"""

from decorator import decorator
from auth_connectors import AWSConnector, CustomAuthConnector,FirebaseConnector

auth_class_dict = {"aws" : AWSConnector.AWSAuth,
                    "firebase" : FirebaseConnector.FirebaseAuth,
                    "custom_auth" : CustomAuthConnector.CustomAuth}
@decorator
class AuthEngine:

    """
        #FIXME
    """

    def __init__(self,func,*args, **kwargs):

        self.auth_type = kwargs.get("auth_type")
        self.select_auth_class(func)

    def select_auth_class(self,func,*args,**kwargs):

        """
            Note:
            1. The __init__ method takes care of calling the functions at the auth_connectors.
        """

        class_instant = auth_class_dict.get(self.auth_type)(*args,**kwargs)

        # returns the original calling function of this decorator
        return func(*args,**kwargs)
