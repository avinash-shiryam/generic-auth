"""
Authentication and Authorisation adapter module
"""

from decorator import decorator
from auth_connectors import aws_connector, custom_auth_connector, firebase_connector

auth_class_dict = {
    "aws": aws_connector.AWSAuth,
    "firebase": firebase_connector.FirebaseAuth,
    "custom_auth": custom_auth_connector.CustomAuth,
}


@decorator
class AuthEngine:

    """
    1. The AuthEngine takes care of calling the respective auth service with the "auth_type" variable provided to it.
    2. This class acts as a decorator, and to call it
        1. Create a function over which you want to use this decorator, and add it.
        2. Call the function from wherever necessary to initialise and run the AuthEngine.
    """

    def __init__(self, func, *args, **kwargs):

        self.auth_type = kwargs.get("auth_type")
        self.select_auth_class(func)

    def select_auth_class(self, func, *args, **kwargs):

        """
        Note:
        1. The __init__ method takes care of calling the functions at the auth_connectors.
        """

        # a default "auth_type", in case if anything isn't passed.
        if not self.auth_type:
            self.auth_type = "custom_auth"
            
        class_instant = auth_class_dict.get(self.auth_type)(*args, **kwargs)

        # returns the original calling function of this decorator
        return func(*args, **kwargs)
