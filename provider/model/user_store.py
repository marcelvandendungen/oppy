import copy
from requests.structures import CaseInsensitiveDict


class UserStore:
    """
      Simple in-memory store for user info. Attribute names are case-insensitive.
      Users can be retrieved by id or username
    """

    def __init__(self):
        self.users = CaseInsensitiveDict()  # key = id
        self.names = CaseInsensitiveDict()  # key = username

    def add(self, user_info):
        self._add_default_attributes(user_info)
        self.users[user_info.get('id')] = dict(user_info)
        self.names[user_info.get('username')] = dict(user_info)
        return id

    def get_by_id(self, id):
        return self.users.get(id, None)

    def get_by_name(self, username):
        return self.names.get(username, None)

    def update_scopes(self, username, scopes):
        self.users[username]['consented_scopes'] += ' ' + scopes

    def list(self):
        """
          Returns a list of dictionaries representing users.
          password and consented_scopes attributes are not returned
        """
        return [self._copy_user(u[1]) for u in self.users.items()]

    def _copy_user(self, user):
        d = copy.deepcopy(dict(user))
        self._del_default_attributes(d)
        return d

    def _add_default_attributes(self, user_info):
        if 'consented_scopes' not in user_info:
            user_info['consented_scopes'] = ''

    def _del_default_attributes(self, dictionary):
        del dictionary['consented_scopes']
        del dictionary['password']


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
