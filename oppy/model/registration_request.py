import time

from oppy.model.client_store import client_store
from oppy.model import crypto


class RegistrationError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class RegistrationRequest:
    "Class to handle the client registration request"

    def __init__(self, parameters):
        self.parameters = parameters.copy()

        # check mandatory parameter
        if 'redirect_uris' not in parameters:
            raise RegistrationError('invalid_redirect_uri', 'redirect_uris is missing')

        # TODO: reject any redirect_uris that have http protocol and hostname other than localhost

        # set proper defaults if parameter omitted
        self.ensure_default('response_types', 'code')
        self.ensure_default('grant_types', 'authorization_code')
        self.ensure_default('token_endpoint_auth_method', 'client_secret_basic')

        # remove anything passed by caller we do not support
        self.remove_unsupported('grant_types', 'implicit')
        self.remove_unsupported('grant_types', 'password')

        # generate response parameters
        self.parameters['client_id'] = str(crypto.generate_client_id())
        self.parameters['client_id_issued_at'] = self.epoch()
        # do not generate client_secret for public clients
        if not self.is_public_client():
            self.parameters['client_secret'] = crypto.generate_client_secret()
            self.parameters['client_secret_expires_at'] = 0

        client_store.add(self.parameters)

    def ensure_default(self, key, value):
        if key not in self.parameters:
            self.parameters[key] = value

    def remove_unsupported(self, key, value):
        if value in self.parameters[key]:
            self.parameters[key].remove(value)

    def is_public_client(self):
        return self.parameters['token_endpoint_auth_method'] == 'None'

    def epoch(self):
        return int(time.time())

    @classmethod
    def from_dictionary(cls, parameters):
        return RegistrationRequest(parameters)

    @property
    def client(self):
        return self.parameters
