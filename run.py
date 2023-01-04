from main import AuthEngine

@AuthEngine
def runner_function(auth_type,*args,**kwargs):
    return "executed and shit json"