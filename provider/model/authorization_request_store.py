

class AuthorizationRequestStore:
    """
      Simple in-memory store for authorization requests
    """

    def __init__(self):
        # authorization requests stored by authorization code
        self.authorization_requests = {}

    def add(self, request_info):
        self.authorization_requests[request_info['code']] = request_info

    def pop(self, code):
        return self.authorization_requests.pop(code, None)


authorization_requests = AuthorizationRequestStore()
