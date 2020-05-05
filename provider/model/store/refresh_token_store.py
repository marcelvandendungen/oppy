

class RefreshTokenStore:
    def __init__(self):
        self._refresh_tokens = {}

    def add(self, refresh_token, principal_info):
        self._refresh_tokens[refresh_token] = principal_info

    def get(self, refresh_token):
        return self._refresh_tokens.get(refresh_token)


refresh_token_store = RefreshTokenStore()
