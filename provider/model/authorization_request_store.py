

class AuthorizationRequestStore:
    """
      Simple in-memory store for authorization requests
    """

    def __init__(self):
        # authorization requests stored by authorization code
        self.authorization_requests = {}

    def add(self, request_info):
        self.authorization_requests[request_info['code']] = request_info

    def get(self, client_id):
        return self.authorization_requests.get(client_id)

    def update(self, client_id, user_info):
        self.authorization_requests[client_id].update(user_info)


authorization_requests = AuthorizationRequestStore()
