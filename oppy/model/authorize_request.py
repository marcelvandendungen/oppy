from urllib.parse import urlencode
from oppy.model import crypto
from oppy.model.authorization_request_store import authorization_requests


class BadAuthorizeRequestError(RuntimeError):
    def __init__(self, error, error_description, error_uri=""):
        self.error = error
        self.error_description = error_description
        self.error_uri = error_uri


class AuthorizeRequestError(RuntimeError):
    def __init__(self, error, error_description, error_uri=""):
        self.error = error
        self.error_description = error_description
        self.error_uri = error_uri


class AuthorizeRequest:
    "Class to handle the OIDC code flow authorization request"

    def __init__(self, dictionary):
        self.parameters = dictionary
        self.parameters.require = self.require

    @classmethod
    def from_dictionary(cls, parameters):
        return AuthorizeRequest(parameters)

    def require(self, key_name, error):
        if key_name not in self.parameters:
            raise error
        return self.parameters[key_name]

    def validate(self, client_store):
        "Handles initial redirect to OP, validates query parameters"

        client = self.lookup_client(client_store)

        self.response_type = self.require('response_type', AuthorizeRequestError('invalid_request',
                                          'response_type parameter is missing'))

        # only support code flow for now
        if self.response_type != 'code':
            raise AuthorizeRequestError('unsupported_response_type', 'unsupported flow')

        self.override_redirect_uri(client)

        self.validate_pkce(client)

        # if scope specified
        if self.parameters.get('scope'):
            self.scope = self.parameters['scope']

        return self.parameters

    def process(self, client_store):
        "Handles the credential verification and issues the authorization code"

        # client id must identify a registered client
        client = self.lookup_client(client_store)

        # throw Error if username or password missing
        self.require('username', BadAuthorizeRequestError('invalid_request', 'username not found'))
        self.require('password', BadAuthorizeRequestError('invalid_request', 'password not found'))

        self.override_redirect_uri(client)
        self.validate_pkce(client)

        self.code = self.issue_code()

        user_info = self.verify_user_credentials()
        request_info = vars(self).copy()
        del request_info['parameters']

        request_info.update(user_info)
        authorization_requests.add(request_info)

        return self

    def redirection_url(self):
        # redirect to redirect_uri with code and state as query parameters
        query_params = {
            'code': self.code
        }

        if self.parameters.get('state'):
            query_params['state'] = self.parameters['state']

        return self.redirect_uri + '?' + urlencode(query_params)

    def lookup_client(self, client_store):
        "look up client in registered clients by client id"

        # if client id is missing, return bad request response
        self.client_id = self.require('client_id', BadAuthorizeRequestError('invalid_request', 'client_id is missing'))

        client = client_store.get(self.client_id)

        # client = next((item for item in clients if item['client_id'] == self.client_id), None)
        if not client:
            raise BadAuthorizeRequestError('unknown_client', 'Client not registered')

        assert 'redirect_uris' in client
        self.redirect_uri = client['redirect_uris'][0]

        return client

    def override_redirect_uri(self, client):
        """
          If authorization request specifies the redirect uri, validate against whitelisted uris
          If correct, use it. If not specified, use the first whitelisted one.
        """
        if 'redirect_uri' in self.parameters:
            self.redirect_uri = self.parameters['redirect_uri']
            if self.redirect_uri not in client['redirect_uris']:
                raise BadAuthorizeRequestError('invalid_redirect_uri', 'Not a registered redirect uri')

    def validate_pkce(self, client):
        """
          Verify that PKCE query parameters are present and correct for public clients
        """
        if is_public(client):
            self.code_challenge = self.require('code_challenge', AuthorizeRequestError('invalid_request',
                                                                                       'code challenge required'))
            self.code_challenge_method = self.parameters.get('code_challenge_method')
            if not self.code_challenge_method:
                self.code_challenge_method = 'plain'

            if self.code_challenge_method != "S256":
                raise AuthorizeRequestError(302, 'invalid_request', 'Invalid code challenge method')

    def verify_user_credentials(self):
        return {
            'id': 'abcdef',
            'username': 'mvandend'
        }

    def issue_code(self):
        "Generate an authorization code for the request"
        return crypto.generate_code()


def is_public(client):
    return 'token_endpoint_auth_method' in client and client['token_endpoint_auth_method'] == 'None'
