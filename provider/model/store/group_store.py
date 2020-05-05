from requests.structures import CaseInsensitiveDict


class GroupStore:
    """
      Simple in-memory store for group info. Attribute names are case-insensitive.
      Users can be retrieved by id or groupname
    """

    def __init__(self):
        self.groups = CaseInsensitiveDict()  # key = id
        self.names = CaseInsensitiveDict()  # key = groupname

    def add(self, info):
        self.groups[info.get('id')] = info
        self.names[info.get('displayname')] = info
        return id

    def get_by_id(self, id):
        return self.groups.get(id, None)

    def get_by_name(self, username):
        return self.names.get(username, None)


group_store = GroupStore()
