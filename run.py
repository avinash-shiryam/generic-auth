from main import AuthEngine

@AuthEngine
def runner_function(*args,**kwargs):
    return "executed and shit json"