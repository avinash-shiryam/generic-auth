from Engine.main import AuthEngine


@AuthEngine
def runner_function(*args, **kwargs):
    """
    This is an Example function to run the AuthEngine.
    Steps
    1. Create a function like the runner_function here and add the AuthEngine decorator
    2. Add whatever functionality you want inside this function and call the function from wherever necessary, either
        from a function or a class.
    """
    return "function executed successfully"


# need to instantsiate the function with the calling_function variable
runner_function(calling_function="aws")
