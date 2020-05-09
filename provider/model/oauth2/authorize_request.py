import time
from urllib.parse import urlencode
from provider.model import crypto
from provider.model.store.authorization_request_store import authorization_requests
from provider.model.store.user_store import user_store


class AuthenticationError(Exception):
    def __init__(self, error, error_description, error_uri=""):
        self.error = error
        self.error_description = error_description
        self.error_uri = error_uri


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
        return cls(parameters)

    def validate(self, client_store):
        "Handles initial redirect to OP, validates query parameters"

        client = self.lookup_client(client_store)

        self.require('response_type', AuthorizeRequestError('invalid_request',
                     'response_type parameter is missing'))

        # only support code flow for now
        if self.response_type != 'code':
            raise AuthorizeRequestError('unsupported_response_type', 'unsupported flow')

        self.override_redirect_uri(client)

        self.scope = self.validate_scopes(client)

        self.validate_pkce(client)

        return self

    def process(self, client_store, session=None):
        "Handles the credential verification and issues the authorization code"

        # client id must identify a registered client
        client = self.lookup_client(client_store)

        if not session:
            # throw Error if username or password missing
            username = self.require('username', BadAuthorizeRequestError('invalid_request',
                                                                         'username not found'))
            password = self.require('password', BadAuthorizeRequestError('invalid_request',
                                                                         'password not found'))
            user_info = self.verify_user_credentials(username, password)
            self.consented_scopes = user_info['consented_scopes']
            self.username = user_info['username']
            self.id = user_info['username']     # id is used as 'sub' claim in token
            self.name = user_info['name']
        else:
            user_info = session

        self.override_redirect_uri(client)
        self.validate_pkce(client)

        self.code = self.issue_code()

        request_info = vars(self).copy()

        request_info['issued_at'] = int(time.time())

        request_info.update(user_info)
        authorization_requests.add(request_info)

        self.scope = self.validate_scopes(client)

        return self

    def redirection_url(self):
        # redirect to redirect_uri with code and state as query parameters
        query_params = {
            'code': self.code
        }

        if hasattr(self, 'state'):
            query_params['state'] = self.state

        return self.redirect_uri + '?' + urlencode(query_params)

    def redirect_error(self, code):
        # redirect to redirect_uri with error and state as query parameters
        query_params = {
            'error': code
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

    def validate_scopes(self, client):
        allowed_scopes = set(client['scope'].split(' '))
        if hasattr(self, 'scope'):
            requested_scopes = set(self.scope.split(' '))
            if not requested_scopes.issubset(allowed_scopes):
                raise AuthorizeRequestError('invalid_scope', 'One or more scopes are invalid')
            return self.scope     # only prompt for requested scopes
        return client['scope']   # when no scope specified, assume all scopes registered are requested

    def validate_pkce(self, client):
        """
          Verify that PKCE query parameters are present and correct for public clients
        """
        if is_public(client):
            self.require('code_challenge', AuthorizeRequestError('invalid_request', 'code challenge required'))
            if not hasattr(self, 'code_challenge_method'):
                self.code_challenge_method = 'plain'

            if self.code_challenge_method != "S256":
                raise AuthorizeRequestError(302, 'invalid_request', 'Invalid code challenge method')

    def verify_user_credentials(self, username, password):
        user_info = user_store.get_by_name(username)
        if not user_info or user_info['password'] != password:
            raise AuthenticationError('invalid_request', 'username or password incorrect')
        return user_info

    def issue_code(self):
        "Generate an authorization code for the request"
        return crypto.generate_code()

    def require(self, key_name, error):
        if not hasattr(self, key_name):
            raise error
        return getattr(self, key_name)

    def consent_given(self, scope):
        auth_req = authorization_requests.get(self.code)
        requested_scopes = set(scope.split(' '))
        allowed_scopes = set(auth_req['consented_scopes'].split(' '))
        return requested_scopes.issubset(allowed_scopes)

    @property
    def form_post_response(req):
        if hasattr(req, 'response_mode'):
            return req.response_mode == 'form_post'
        return False


def is_public(client):
    return 'token_endpoint_auth_method' in client and client['token_endpoint_auth_method'] == 'None'
