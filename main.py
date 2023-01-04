from decorator import decorator
"""
Authentication and Authorisation adapter module
"""

auth_class_dict = {}
@decorator
class AuthEngine:

    def __init__(self, calling_function,*args, **kwargs):
        self.calling_function = calling_function

    def __call__(self,*args,**kwargs):
        try:
            self.select_auth_class(*args,**kwargs)
        except:
            return "some shit json again with an error"

    def select_auth_class(self,*args,**kwargs):
        self.auth_type = kwargs.get("auth_type")
        auth_class_dict[self.auth_type](**kwargs)
        return self.calling_function(*args,**kwargs)
