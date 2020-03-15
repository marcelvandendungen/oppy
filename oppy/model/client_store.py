

class ClientStore:
    def __init__(self):
        self.clients = {}

    def add(self, client_info):
        self.clients[client_info['client_id']] = client_info

    def get(self, client_id):
        return self.clients.get(client_id)


client_store = ClientStore()
