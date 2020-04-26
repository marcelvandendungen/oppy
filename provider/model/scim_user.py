import hashlib
import urllib
from util import get_iso_datetime
from provider.model.crypto import generate_code
from requests.structures import CaseInsensitiveDict


class ScimUser(CaseInsensitiveDict):
    def __init__(self, data, host_url):
        super().__init__(data)
        now = get_iso_datetime()
        user_id = generate_code(10) if 'id' not in data else data['id']

        self.update({
            'id': user_id,
            'active': True,
            'meta': {
                'resourceType': 'User',
                'created': now,
                'modified': now,
                'location': self.get_location(host_url + '/scim/v2/Users/', user_id),
                'version': self.get_version(now, now)
            }
        })

    @classmethod
    def create_from(cls, parameters, host_url):
        return cls(parameters, host_url)

    @staticmethod
    def get_version(created, modified):
        m = hashlib.md5()
        m.update(str(created).encode() + str(modified).encode())
        return m.hexdigest()

    @staticmethod
    def get_location(prefix, id):
        return urllib.parse.urljoin(prefix, str(id))
