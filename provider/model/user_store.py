from provider.model.crypto import generate_code


class UserStore:
    """
      Simple in-memory store for user info
    """

    def __init__(self):
        self.users = {}

    def add(self, info):

        id = generate_code(16)
        info.update({'id': id})
        self.users[info['username']] = info
        return id

    def get(self, username):
        return self.users.get(username, None)


user_store = UserStore()

user_store.add({
    'username': 'mvandend',
    'password': 'p@ssW0rd!',
    'consent_given': False,
    'name': 'Marcel'})
user_store.add({
    'username': 'testuser',
    'password': 'p@ssW0rd!',
    'consent_given': True,
    'name': 'Test User'})
