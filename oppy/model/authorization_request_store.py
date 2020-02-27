

class AuthorizationRequestStore:

    def __init__(self):
        # authorization requests stored by client id
        self.authorization_requests = {}

    def add(self, request_info):
        self.authorization_requests[request_info['client_id']] = request_info

    def get(self, client_id):
        return self.authorization_requests[client_id]


authorization_requests = AuthorizationRequestStore()
