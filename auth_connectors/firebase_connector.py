from utils.user_utils import response_dict
from utils.local_utils import BaseAuthClass
from utils.local_utils import google_client


class FirebaseAuth(BaseAuthClass):
    def __init__(self, *args, **kwargs):
        self.auth_token = None
        self.type_ = None
        super().executor_function(*args, **kwargs)

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
            kwargs["email"] = decoded_token.get("email")
            kwargs["firebase_phone"] = decoded_token.get("phone_number")
        except Exception as e:
            return response_dict(
                status=401,
                data=None,
                message="Signature expired, login again due to %s" % str(e),
            )

    def check_source_truth(self, *args, **kwargs):
        """
        Note. The check_source_truth functionality must be implemented by the dev themselves.
        """

        pass
