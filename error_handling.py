VISION_LOGIN_ERROR = "Invalid username/password"


class Error_handler(Exception):

        def __init__(self, message):
            self.message = message