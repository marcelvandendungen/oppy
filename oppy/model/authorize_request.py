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

    def validate(self, clients):
        "Handles initial redirect to OP, validates query parameters"

        # if client id is missing, return bad request response
        self.client_id = self.require('client_id', BadAuthorizeRequestError('invalid_request', 'client_id is missing'))
        self.response_type = self.require('response_type', AuthorizeRequestError('invalid_request',
                                          'response_type parameter is missing'))

        client = self.lookup_client(clients)

        # by default redirect to first registered redirect_uri
        assert 'redirect_uris' in client
        self.redirect_uri = client['redirect_uris'][0]

        # only support code flow for now
        if self.response_type != 'code':
            raise AuthorizeRequestError('unsupported_response_type', 'unsupported flow')

        # redirect_uri query parameter is optional, but when specified must match one of the registed URIs
        if 'redirect_uri' in self.parameters:
            # override of the redirect_uri
            self.redirect_uri = self.parameters['redirect_uri']
            if self.redirect_uri not in client['redirect_uris']:
                raise BadAuthorizeRequestError('invalid_redirect_uri', 'Not a registered redirect uri')

        # require PKCE for public clients
        if client['public']:
            self.code_challenge = self.require('code_challenge', AuthorizeRequestError('invalid_request',
                                                                                       'code challenge required'))
            self.code_challenge_method = self.require('code_challenge_method',
                                                      AuthorizeRequestError('invalid_request',
                                                                            'code challenge method required'))
            if self.code_challenge_method != "SHA256":
                raise AuthorizeRequestError(302, 'invalid_request', 'Invalid code challenge method')

        # if scope specified
        if self.parameters.get('scope'):
            self.scope = self.parameters['scope']

        request_info = vars(self).copy()
        del request_info['parameters']

        authorization_requests.add(request_info)

        return self.parameters

    def redirection_url(self, clients):
        "Handles the credential verification and issues the authorization code"

        self.client_id = self.require('client_id', BadAuthorizeRequestError('invalid_request', 'client_id is missing'))

        # throw Error if username or password missing
        self.require('username', BadAuthorizeRequestError('invalid_request', 'username not found'))
        self.require('password', BadAuthorizeRequestError('invalid_request', 'password not found'))

        # TODO: verify user credentials

        # client id must identify a registered client
        client = self.lookup_client(clients)

        assert 'redirect_uris' in client
        self.redirect_uri = client['redirect_uris'][0]

        if 'redirect_uri' in self.parameters:
            # override of the redirect_uri
            self.redirect_uri = self.parameters['redirect_uri']
            if self.redirect_uri not in client['redirect_uris']:
                raise BadAuthorizeRequestError('invalid_redirect_uri', 'Not a registered redirect uri')

        # require PKCE for public clients
        if client['public']:
            self.code_challenge = self.require('code_challenge', AuthorizeRequestError('invalid_request',
                                                                                       'code challenge missing'))
        # redirect to redirect_uri with code and state as query parameters
        query_params = {
            'code': self.issue_code()
        }

        if self.parameters.get('state'):
            query_params['state'] = self.parameters['state']

        return self.redirect_uri + '?' + urlencode(query_params)

    def lookup_client(self, clients):
        "look up client in registered clients by client id"
        client = next((item for item in clients if item['client_id'] == self.client_id), None)
        if not client:
            raise BadAuthorizeRequestError('unknown_client', 'Client not registered')

        return client

    def issue_code(self):
        return crypto.generate_code()
