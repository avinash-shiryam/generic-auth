from config import config_functions

"""
Authentication and Authorisation adapter module
"""

def adapter_data(**kwargs):
    main_dict = kwargs

class mainAdapter:

    def __init__(self, auth_tool):
        self.auth_tool = auth_tool

    def selector_func(self):        
        config_functions(self.auth_tool)()
