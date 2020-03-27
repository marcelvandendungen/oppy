

class Client(dict):
    def __init__(self, *arg, **kw):
        super(Client, self).__init__(*arg, **kw)

    def is_public(self):
        return 'token_endpoint_auth_method' in self and self['token_endpoint_auth_method'] == 'None'


class ClientStore:
    def __init__(self):
        self._clients = {}
        self._clients['confidential_client'] = Client({
            'client_id': 'confidential_client',
            # redirect_uris must be absolute URLs, may contain query params, may not contain fragment
            'redirect_uris': ['https://localhost:5001/cb', 'https://localhost:5003/cb'],
            'token_endpoint_auth_method': 'client_secret_basic'
        })
        self._clients['public_client'] = Client({
            'client_id': 'public_client',
            'redirect_uris': ['https://localhost:5002/cb'],
            'token_endpoint_auth_method': 'None'
        })

    def add(self, client_info):
        self._clients[client_info['client_id']] = Client(client_info)

    def get(self, client_id):
        return self._clients.get(client_id)


client_store = ClientStore()
