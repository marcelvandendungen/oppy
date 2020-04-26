from requests.structures import CaseInsensitiveDict


class UserStore:
    """
      Simple in-memory store for user info
    """

    def __init__(self):
        self.users = CaseInsensitiveDict()

    def add(self, info):
        self.users[info.get('id')] = info
        return id

    def get(self, username):
        return self.users.get(username, None)

    def update_scopes(self, username, scopes):
        self.users[username]['consented_scopes'] += ' ' + scopes


user_store = UserStore()

user_store.add({
    'id': 'hh1FRC4TNg',
    'username': 'mvandend',
    'password': 'p@ssW0rd!',
    'consented_scopes': '',
    'name': 'Marcel'})
user_store.add({
    'id': 'rii8EHQPrx',
    'username': 'testuser',
    'password': 'p@ssW0rd!',
    'consented_scopes': 'openid read write',
    'name': 'Test User'})
