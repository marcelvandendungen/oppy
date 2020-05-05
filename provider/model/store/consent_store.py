from provider.model.crypto import generate_code


class ConsentStore:
    """
      Simple in-memory store for consent info
    """

    def __init__(self):
        self.consent_info = {}

    def add(self, info):

        id = generate_code(16)
        self.consent_info[id] = info
        return id

    def get(self, id):
        return self.consent_info.pop(id, None)


consent_store = ConsentStore()
