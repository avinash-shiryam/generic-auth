"""
The following is an example on how to use the Auth Engine

1. The data passed to the Auth Engine will be a jwt which has three components -> "header, payload, signature"
2. We will be sending the header to the AuthEngine using a decorator and the the result accompanied will be returned to the calling function

Steps to cold start the engine?

1. Import auth engine
2. create a wrapper function, on top of which the decorator acts
3. the decrypted jwt data will be receieved, and further opearations can be done

Notes:
1. Currently there are three types of auth which are supported (pass these directly with auth_type)
    1. aws
    2. firebase
    3. custom_auth 
"""

from engine.main import AuthEngine


@AuthEngine(auth_typ="aws")
def some_runner_function(*args, **kwargs):

    print(f"received arguments after decryption from authz process are {kwargs}")

    return kwargs


# call the function from this file or any other module of the project either directly or using a decorator call
some_runner_function(
    request_headers="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IjEyMyIsImlhdCI6MTY3NDM3MjgwMn0.IHYJDVezjZHUpbvcBsDjUfG3l1m18As6b_L87XzuXDk"
)
