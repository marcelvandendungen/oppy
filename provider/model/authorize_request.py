import time
from urllib.parse import urlencode
from provider.model import crypto
from provider.model.authorization_request_store import authorization_requests
from provider.model.user_store import user_store


class BadAuthorizeRequestError(Exception):
    def __init__(self, error, error_description, error_uri=""):
        self.error = error
        self.error_description = error_description
        self.error_uri = error_uri


class AuthorizeRequestError(Exception):
    def __init__(self, error, error_description, error_uri=""):
        self.error = error
        self.error_description = error_description
        self.error_uri = error_uri


class AuthorizeRequest:
    "Class to handle the OIDC code flow authorization request"

    def __init__(self, *dictionaries, **kwargs):
        for dictionary in dictionaries:
            for key in dictionary:
                setattr(self, key, dictionary[key])
        for key in kwargs:
            setattr(self, key, kwargs[key])

    def __iter__(self):
        for attr, value in self.__dict__.items():
            if not callable(attr):
                yield attr, value

    @classmethod
    def from_dictionary(cls, parameters):
        return AuthorizeRequest(parameters)

    def validate(self, client_store):
        "Handles initial redirect to OP, validates query parameters"

        client = self.lookup_client(client_store)

        self.require('response_type', AuthorizeRequestError('invalid_request',
                     'response_type parameter is missing'))

        # only support code flow for now
        if self.response_type != 'code':
            raise AuthorizeRequestError('unsupported_response_type', 'unsupported flow')

        self.override_redirect_uri(client)

        self.validate_pkce(client)

        return self

    def process(self, client_store):
        "Handles the credential verification and issues the authorization code"

        # client id must identify a registered client
        client = self.lookup_client(client_store)

        # throw Error if username or password missing
        username = self.require('username', BadAuthorizeRequestError('invalid_request',
                                                                     'username not found'))
        password = self.require('password', BadAuthorizeRequestError('invalid_request',
                                                                     'password not found'))

        self.override_redirect_uri(client)
        self.validate_pkce(client)

        self.code = self.issue_code()

        user_info = self.verify_user_credentials(username, password)
        request_info = vars(self).copy()

        request_info['issued_at'] = int(time.time())

        request_info.update(user_info)
        authorization_requests.add(request_info)

        return self

    def redirection_url(self):
        # redirect to redirect_uri with code and state as query parameters
        query_params = {
            'code': self.code
        }

        if hasattr(self, 'state'):
            query_params['state'] = self.state

        return self.redirect_uri + '?' + urlencode(query_params)

    def lookup_client(self, client_store):
        "look up client in registered clients by client id"

        # if client id is missing, return bad request response
        self.require('client_id', BadAuthorizeRequestError('invalid_request', 'client_id is missing'))

        client = client_store.get(self.client_id)

        if not client:
            raise BadAuthorizeRequestError('unknown_client', 'Client not registered')

        return client

    def override_redirect_uri(self, client):
        """
          If authorization request specifies the redirect uri, validate against whitelisted uris
          If correct, use it. If not specified, use the first whitelisted one.
        """
        registered_uris = client['redirect_uris']
        if hasattr(self, 'redirect_uri'):
            if self.redirect_uri not in registered_uris:
                raise BadAuthorizeRequestError('invalid_redirect_uri', 'Not a registered redirect uri')
        else:
            self.redirect_uri = registered_uris[0]

    def validate_pkce(self, client):
        """
          Verify that PKCE query parameters are present and correct for public clients
        """
        if is_public(client):
            self.require('code_challenge', AuthorizeRequestError('invalid_request', 'code challenge required'))
            if not self.code_challenge_method:
                self.code_challenge_method = 'plain'

            if self.code_challenge_method != "S256":
                raise AuthorizeRequestError(302, 'invalid_request', 'Invalid code challenge method')

    def verify_user_credentials(self, username, password):
        user_info = user_store.get(username)
        if not user_info or user_info['password'] != password:
            raise BadAuthorizeRequestError('invalid_request', 'username or password incorrect')
        return user_info

    def issue_code(self):
        "Generate an authorization code for the request"
        return crypto.generate_code()

    def require(self, key_name, error):
        if not hasattr(self, key_name):
            raise error
        return getattr(self, key_name)

    @property
    def user_has_given_consent(self):
        auth_req = authorization_requests.get(self.code)
        return auth_req['consent_given']


def is_public(client):
    return 'token_endpoint_auth_method' in client and client['token_endpoint_auth_method'] == 'None'
