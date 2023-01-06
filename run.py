from main import AuthEngine

"""
->example function which uses the AuthEngine as a decorator and performs the authentication process
To run:
1. 
"""
@AuthEngine
def runner_function(*args,**kwargs):
    return "functione executed successfully"