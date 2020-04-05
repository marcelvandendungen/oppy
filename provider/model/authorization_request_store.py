

class AuthorizationRequestStore:
    """
      Simple in-memory store for authorization requests
    """

    def __init__(self):
        # authorization requests stored by authorization code
        self.authorization_requests = {}

    def add(self, request_info):
        # logger.info("Adding code: " + request_info['code'])
        self.authorization_requests[request_info['code']] = request_info

    def get(self, code):
        # logger.info("Popping code: " + code)
        return self.authorization_requests.get(code, None)

    def pop(self, code):
        # logger.info("Popping code: " + code)
        return self.authorization_requests.pop(code, None)


authorization_requests = AuthorizationRequestStore()
