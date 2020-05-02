from provider.model.crypto import generate_code
from provider.model.scim_entity import ScimEntity, ScimError


class ScimGroup(ScimEntity):
    def __init__(self, data, host_url):
        super().__init__(data)

        if 'schemas' not in data or 'urn:ietf:params:scim:schemas:core:2.0:Group' not in data['schemas']:
            raise ScimError(400, detail='Unsupported schema', scim_type='invalidValue')

        group_id = generate_code(10) if 'id' not in data else data['id']
        self.update(self.get_metadata(data, group_id, 'Group', host_url))
