

class Client(dict):
    def __init__(self, *arg, **kw):
        super(Client, self).__init__(*arg, **kw)

    def is_public(self):
        return 'token_endpoint_auth_method' in self and self['token_endpoint_auth_method'] == 'None'


class ClientStore:
    def __init__(self):
        self._clients = {}

    def add(self, client_info):
        self._clients[client_info['client_id']] = Client(client_info)

    def get(self, client_id):
        return self._clients.get(client_id)


client_store = ClientStore()
