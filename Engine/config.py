"""
Config loading class
"""
import os
from redis import Redis
from utils.aws_utils import get_secret
from Engine.constants import AWS_SECRET_DEV, AWS_SECRET_PROD, AWS_REGION

os.environ.setdefault("APP_SETTINGS", "local")


class ConfigVariable:
    __secrets = get_secret(secret_id=AWS_SECRET_PROD, region=AWS_REGION)
    NIUM_ACCESS_TOKEN_DICT = Redis.from_url(__secrets.get("nium_access_token_dict_url"))

    # common secrets
    IS_SECURE = False
    COGNITO_USER_POOL_ID = __secrets.get("POOL2")
    APP_SETTINGS = os.environ.get("APP_SETTINGS")
    AWS_REGION = AWS_REGION
    SENDER = "contact@salt.pe"
    BUCKET_PATH = ""
    LOGS_BUCKET_NAME = "code-base-log"
    S3_URL = ""
    DOCUMENTS_FOLDER_PATH = "documents"
    AUTHBRIDGE_USERNAME = "prod.saltpe@authbridge.com"
    NIUM_CALLBACK_SECRET = __secrets.get("nium_callback_secret")
    COGNITO_APP_CLIENT_ID = __secrets.get("POOL2CLIENTID")
    AUTH_TOKEN = __secrets.get("AUTH_TOKEN").split(", ")
    USERNAME = __secrets.get("USERNAME").split(", ")
    PASSWORD = __secrets.get("PASSWORD")
    POOL1 = __secrets.get("POOL1")
    POOL1CLIENTID = __secrets.get("POOL1CLIENTID")
    POOL2 = __secrets.get("POOL2")
    POOL2CLIENTID = __secrets.get("POOL2CLIENTID")
    COGNITO_KEYS_URL = (
        "https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json".format(
            AWS_REGION, COGNITO_USER_POOL_ID
        )
    )
    COGNITO_KEYS_URL1 = "https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json"
    PROTECTED_PATH = "{cwd}/app/preview/protected".format(cwd=os.getcwd())
    BUGSNAG_API = __secrets.get("BUGSNAGAPI")
    WHATSAPP_TEMPLATE_URL = __secrets.get("WHATSAPP_TEMPLATE_URL")
    WHATSAPP_API_SECRET = __secrets.get("WHATSAPP_API_SECRET_TEMPLATE")
    TOKENIZATION_PROXY = __secrets.get("TOKENIZATION_PROXY")
    TOKENIZATION_SECRET = __secrets.get("TOKENIZATION_SECRET")
    LEAD_SQUARED_SECRET = __secrets.get("LEAD_SQUARED_SECRET")
    CURRENCY_API_KEY = __secrets.get("CURRENCY_API_KEY")
    CASHFREE_API_KEY = __secrets.get("CASHFREE_API_KEY")
    SALTOPGSP_API_KEY = __secrets.get("SALTOPGSP_API_KEY")
    DOC_API_KEY = __secrets.get("DOC_API_KEY")
    CAPTCHA_URL = (
        "https://www.google.com/recaptcha/api/siteverify?secret={}&response={}"
    )
    CAPTCHA_SECRET = __secrets.get("CAPTCHA_SECRET")
    AML_URL = "https://1ipxthgyb7.execute-api.ap-south-1.amazonaws.com/staging"
    AML_SECRET = __secrets.get("AML_SECRET")
    SALT_CASHFREE_CRM_SECRET = __secrets.get("SALT_CASHFREE_CRM_SECRET")
