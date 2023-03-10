from utils.user_utils import response_dict
from utils.local_utils import BaseAuthClass
from engine.config import local_mock_db
from decorator import decorator


@decorator
class FirebaseAuth(BaseAuthClass):
    def __init__(self, func, *args, **kwargs):
        self.auth_token = None
        self.type_ = None
        super().executor_function(func, *args, **kwargs)

    def parse_headers(self, *args, **kwargs):
        self.auth_token = super().parse_headers()
        if self.auth_token:
            token_info = self.auth_token.split(" ")
            self.type_ = token_info[0]
            self.auth_token = token_info[1]
        else:
            return response_dict(status=401, data=None, message="No Authorization")

    def validate_auth(self, *args, **kwargs):
        if self.type_ != "Bearer":
            return response_dict(
                status=401, data=None, message="Invalid auth token type"
            )
        try:
            decoded_token = google_client.verify_id_token(self.auth_token)
            kwargs["user_sub"] = decoded_token.get("sub")
            kwargs["id"] = decoded_token.get("id")
            kwargs["user_name"] = decoded_token.get("user_name")
        except Exception as e:
            return response_dict(
                status=401,
                data=None,
                message="Signature expired, login again due to %s" % str(e),
            )

    def check_source_truth(self, *args, **kwargs):
        """
        Note. The check_source_truth functionality must be implemented by the dev themselves.

        1. The kwargs which contain data from check source of truth will be returned to the calling function
        """

        return kwargs
