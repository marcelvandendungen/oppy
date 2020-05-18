import hashlib
from provider.util import get_iso_datetime
from requests.structures import CaseInsensitiveDict


class ScimError(Exception):
    def __init__(self, status, detail=None, scim_type=None):
        self.status = status
        self.detail = detail
        self.scim_type = scim_type


class ScimEntity(CaseInsensitiveDict):

    def get_metadata(self, data, id, type, host_url):
        created = self.get_date(data, 'created')
        modified = self.get_date(data, 'modified')
        return {
            'id': id,
            'active': True,
            'meta': {
                'resourceType': type,
                'created': created,
                'modified': modified,
                'location': '{0}/scim/v2/{1}s/{2}'.format(host_url, type, id),
                'version': self.get_version(created, modified)
            }
        }

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

    @classmethod
    def create_from(cls, parameters, host_url):
        return cls(parameters, host_url)
