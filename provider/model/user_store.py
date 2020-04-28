from requests.structures import CaseInsensitiveDict


class UserStore:
    """
      Simple in-memory store for user info. Attribute names are case-insensitive.
      Users can be retrieved by id or username
    """

    def __init__(self):
        self.users = CaseInsensitiveDict()  # key = id
        self.names = CaseInsensitiveDict()  # key = username

    def add(self, info):
        self.users[info.get('id')] = info
        self.names[info.get('username')] = info
        return id

    def get_by_id(self, id):
        return self.users.get(id, None)

    def get_by_name(self, username):
        return self.names.get(username, None)

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
