"""
Authentication and Authorisation adapter module
"""

from decorator import decorator
import services

auth_class_dict = {"aws" : services.AWSAuth}
@decorator
class AuthEngine:

    def __init__(self, calling_function,*args, **kwargs):

        self.calling_function = calling_function
        self.select_auth_class(*args,**kwargs)

    def select_auth_class(self,*args,**kwargs):
        self.auth_type = kwargs.get("auth_type")

        #creating an instance of the class
        class_instant = auth_class_dict.get(self.auth_type)(*args,**kwargs)

        # returns the original calling function of this decorator
        return self.calling_function(*args,**kwargs)
