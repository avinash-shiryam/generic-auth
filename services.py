class AWSAuth:

    def __init__(self,*args,**kwargs):
        if "condition":
            self.parse_headers(*args,**kwargs)
        else:
            return "some_error"

    def parse_headers(self,*args,**kwargs):
        if "condition":
            self.validate_auth(*args,**kwargs)
        else:
            return "some_error"

    def validate_auth(self,*args,**kwargs):
        if "condition":
            self.check_source(*args,**kwargs)
        else:
            return "some_error"

    def check_source(self,*args,**kwargs):
        if "condition":
            # done
            pass
        else:
            return "some_error"