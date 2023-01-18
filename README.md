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

### Notes

#### Misc.
+ The response_dict which is used across authentication methods uses flask. It can be found under 'utils/user_utils.py'

#### Firebase
1. The "gcp_secret" must be embedded into a environment variable, instance present at "local_utils.py".
#### CustomAuth
1. To run the custom authentication, the secret key must be embedded as an "environment variavle" -> "SECRET_KEY".

#### AWS
1. Populate constants.py with the following variables "AWS_SECRET_DEV", "AWS_SECRET_PROD", "AWS_REGION".

##### Still confused?. Checkout the *exampleAuth.py* inside **examples/** directory


