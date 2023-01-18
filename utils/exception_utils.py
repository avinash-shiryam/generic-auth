"""
Utils script containing exceptions and handlers for exceptions.
"""
import flask


class ParameterError(Exception):
    """Raise for errors when all params are not specified"""

    def __init__(self, message="Not enough/ Wrong params entered"):
        self.message = message
        super().__init__(self.message)
        return flask.abort(400, self.message)


class UserUnauthorizedError(Exception):
    """Raise for errors when user does not have access to the group id"""

    def __init__(self, message="The user is not authorized."):
        self.message = message
        super().__init__(self.message)
        return flask.abort(400, self.message)


class NoAuthTokenPresentError(Exception):
    """Raised when token is not present"""

    def __init__(self, message="Auth token required"):
        self.message = message
        super().__init__(self.message)
        return flask.abort(400, self.message)


class PhoneError(Exception):
    """Raised when phone number is already present"""

    def __init__(self, message="Phone number is already present."):
        self.message = message
        super().__init__(self.message)
        return flask.abort(400, self.message)


class NotAllowedError(Exception):
    """Raised when the further flow is restricted for the current user."""

    def __init__(self, message="User not allowed to proceed further."):
        self.message = message
        super().__init__(self.message)
        return flask.abort(400, self.message)


class InvalidNumberError(Exception):
    """Raised when phone number is invalid"""

    def __init__(self, message="Please re-try after entering a valid Phone Number."):
        self.message = message
        super().__init__(self.message)
        return flask.abort(400, self.message)


class DocumentError(Exception):
    """Raise for errors when content type is not Document"""

    def __init__(self, message="Content type is not Document"):
        self.message = message
        super().__init__(self.message)
