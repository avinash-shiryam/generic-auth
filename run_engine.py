from Engine.main import AuthEngine

"""
->example function which uses the AuthEngine as a decorator and performs the authentication process
To run:
1. 
"""

@AuthEngine
def runner_function(*args,**kwargs):
    return "functione executed successfully"

# need to instantsiate the function with the calling_function variable
runner_function(calling_function="aws")