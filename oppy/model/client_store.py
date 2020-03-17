

class ClientStore:
    def __init__(self):
        self._clients = {}
        self._clients['confidential_client'] = {
            'client_id': 'confidential_client',
            # redirect_uris must be absolute URLs, may contain query params, may not contain fragment
            'redirect_uris': ['http://localhost:5001/cb', 'http://localhost:5003/cb'],
            'public': False
        }
        self._clients['public_client'] = {
            'client_id': 'public_client',
            'redirect_uris': ['http://localhost:5002/cb'],
            'public': True
        }

    def add(self, client_info):
        self._clients[client_info['client_id']] = client_info

    def get(self, client_id):
        return self._clients.get(client_id)


client_store = ClientStore()
