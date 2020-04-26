import hashlib
import urllib
from util import get_iso_datetime
from provider.model.crypto import generate_code
from requests.structures import CaseInsensitiveDict


class ScimUser(CaseInsensitiveDict):
    def __init__(self, data, host_url):
        super().__init__(data)
        user_id = generate_code(10) if 'id' not in data else data['id']
        created = self.get_date(data, 'created')
        modified = self.get_date(data, 'modified')

        self.update({
            'id': user_id,
            'active': True,
            'meta': {
                'resourceType': 'User',
                'created': created,
                'modified': modified,
                'location': self.get_location(host_url + '/scim/v2/Users/', user_id),
                'version': self.get_version(created, modified)
            }
        })

    @classmethod
    def create_from(cls, parameters, host_url):
        return cls(parameters, host_url)

    @staticmethod
    def get_version(created, modified):
        m = hashlib.md5()
        m.update(str(created).encode() + str(modified).encode())
        return 'W/"{0}"'.format(m.hexdigest())

    def get_etag(self):
        return self.get_version(self['meta']['created'], self['meta']['modified'])

    def get_date(self, data, field):
        if 'meta' not in data:
            return get_iso_datetime()

        return get_iso_datetime() if field not in data['meta'] else data['meta'][field]


    @staticmethod
    def get_location(prefix, id):
        return urllib.parse.urljoin(prefix, str(id))
