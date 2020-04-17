
class UserStore:
    """
      Simple in-memory store for user info
    """

    def __init__(self):
        self.users = {}

    def add(self, info):

        self.users[info['username']] = info
        return id

    def get(self, username):
        return self.users.get(username, None)

    def update_scopes(self, username, scopes):
        self.users[username]['consented_scopes'] += ' ' + scopes


user_store = UserStore()

user_store.add({
    'username': 'mvandend',
    'password': 'p@ssW0rd!',
    'consented_scopes': '',
    'name': 'Marcel'})
user_store.add({
    'username': 'testuser',
    'password': 'p@ssW0rd!',
    'consented_scopes': 'openid read write',
    'name': 'Test User'})
