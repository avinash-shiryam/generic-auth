# Auth Engine

### What does it do?

+ This engine is a common decorator for integrating the **header parse**, **auth validation** and **Checking source of truth** functionality for any authorisation and authentication server.

### What's the hierarchy?

1. The project is divided into 3 parts
    1. **connectors/**
        + The connectors contain the individual components which connect with the auth server.
    2. **Engine/**
        + Engine contains the central component for running the instances based on the params supplied
    3. **utils/**
        + Utils contain any additional files required which are either required to support or provide data and accessability to the connector files.

### How does it work

1. Whenever the run_engine is instantsiated with the decorator, the **Engine/** is called upon and the params are supplied to the connector.
2. The connectors hold the logic for the supply and management of auth tokens to and from the auth server.
3. The connectors contain the logic on how to communicate with the server. Some of the basic functionality is inferred from a exampleAuthFunction from the **Utils/** directory


### How do you run it?

1. First, create or modify a connector based on the requirement in the **connectors/** directory.
2. Index the directory into a dictionary, into the **main.py** which is present in the **Engine/** 
3. Run!

### How do you create an Auth connector of your own?
```
class AuthAsExample():

    """
    There are three functions which contribute in the authentication pipeline
    1. parse_headers
    2. validate_auth
    3. check_source_truth
    """

    def __init__(self, *args, **kwargs):
        self.auth_token = None
        self.message = None
        self.public_key = None
        self.decoded_signature = None
        self.executor_function(*args, **kwargs)

    def executor_function(self, *args, **kwargs):
        self.parse_headers(self)
        self.validate_auth(self)
        self.check_source_truth(self)

    def parse_headers(self, *args, **kwargs):

        """
        1. The parse headers function extracts the necessary components from the headers which are sent from the server.
        2. Now "AUTHORISATION" is parsed from the headers and a function named "get_contents()" which is under abstraction for this case is used to fetch the variables such as
             message, public_key etc etc.
        3. Now after the extraction of these, if the parsing goes on successfully, it is verified in the next stage.
        """

        if "AUTHORIZATION" in request.headers or "auth_token" in request.view_args:
            self.auth_token = request.headers.get(
                "AUTHORIZATION"
            ) or request.view_args.get("auth_token")
        self.message, self.public_key, self.decoded_signature = self.get_contents(
            self.auth_token
        )

    def validate_auth(self, *args, **kwargs):

        """
        1. Now the message, public key, and decoded signature from the parse_headers() function must be verified/ authenticated.
        2. Now if the message verification against the public key fails, an exception is raised and the pipeline breaks.
        3. After the initial verification, the claims are now verified with a local source of truth, which happens in the next function.
        """

        if not self.public_key.verify(
            self.message.encode("utf8"), self.decoded_signature
        ):
            # Signature verification failed
            logging.info("signature verification failed")
            # return to executor_function as failed
            self.executor_function(status_token="header_fail")
            raise exception_utils.UserUnauthorizedError(message="Authentication failed")

    def check_source_truth(self, *args, **kwargs):

        """
        1. The check_source_truth() function carries out the check source of truth functionality of the authentication pipeline
        2. Here, the params which are pased throughout the authentication flow are compared against a local point of truth such as a database or a key
        3. This step helps prevent un recognised login attempts or authorisation attempts.
        4. The function below will now compare if the recieved details actually match with the user_dict which is present above.
        5. If the details match and there is a success response, then the flow continues, else an exception is raised an it breaks.
        """

        user_dict = {
            #   "user_id" : "name"
            "001": "John Doe",
            "002": "John F. Doe",
            "003": "John Dove",
            "004": "John Santoor",
            "005": "Michael hates Faraday",
            "006": "Albert Kills Einstein",
            "007": "Isaac dumb Newton",
        }

        try:
            self.user_obj = user_dict.get(params={"user_sub": self.sub})
            if not self.user_obj:
                logging.info("no user")
                raise exception_utils.UserUnauthorizedError(
                    message="Authentication failed"
                )
            elif self.user_obj:
                kwargs["id"] = self.user_obj.id
                kwargs["user_sub"] = self.user_obj.user_sub
                kwargs["email_id"] = self.user_obj.email_id
                g.user_id = self.user_obj.id
            else:
                g.user_id = -1
        except:
            raise exception_utils.NoAuthTokenPresentError

```
### Notes

#### Misc.
+ The response_dict which is used across authentication methods uses Flask. It can be found under 'utils/user_utils.py'. If your application doesnt use Flask, create a generic one of migrate it to your framework.

#### Firebase
1. The "gcp_secret" must be embedded into a environment variable, instance present at "local_utils.py".
#### CustomAuth
1. To run the custom authentication, the secret key must be embedded as an "environment variavle" -> "SECRET_KEY".

#### AWS
1. Populate constants.py with the following variables "AWS_SECRET_DEV", "AWS_SECRET_PROD", "AWS_REGION".

##### Still confused?. Checkout the *exampleAuth.py* inside **examples/** directory


