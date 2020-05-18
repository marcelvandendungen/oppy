import base64
import time

from abc import ABCMeta, abstractmethod

from provider.model.store.authorization_request_store import authorization_requests
from provider.model.store.refresh_token_store import refresh_token_store
from provider.util import require

FIVEMINUTES = 5 * 60


class GrantError(Exception):
    pass


class Grant:
    """
      Class to handle specifics of validating each grant. Derived classes must implement the validate
      method.
    """
    __metaclass__ = ABCMeta

    def __init__(self, client_store):
        self.client_store = client_store

    @abstractmethod
    def validate(self):
        pass

    def verify_client_credentials(self, client, request):
        if client['token_endpoint_auth_method'] == 'client_secret_basic' or \
           client['token_endpoint_auth_method'] == 'client_secret_post':
            id, secret = self.extract_credentials(request)
            if id != client['client_id']:
                raise GrantError('invalid_request', 'Invalid client id')
            if secret != client['client_secret']:
                raise GrantError('invalid_request', 'Incorrect client secret')
        else:
            raise GrantError('invalid_client', 'Could not verify client credentials')

    def extract_credentials(self, request):
        if 'Authorization' in request.headers:
            return self.extract_basic_credentials(request.headers['Authorization'])
        else:
            return self.extract_post_credentials(request)

    def extract_basic_credentials(self, authorization_header):
        if not authorization_header.startswith('Basic '):
            raise GrantError('invalid_request', 'not basic auth')
        encoded = authorization_header[6:]
        raw = base64.b64decode(encoded.encode('utf-8')).decode('utf-8')
        client_id, client_secret = raw.split(':')
        return client_id, client_secret

    def extract_post_credentials(self, request):
        client_id = request.form['client_id']
        client_secret = request.form['client_secret']
        return client_id, client_secret


class AuthorizationCodeGrant(Grant):
    """
      Validates authorization code grant.
      https://tools.ietf.org/html/rfc6749#section-4.1
    """
    def __init__(self, client_store):
        super().__init__(client_store)

    def validate(self, request):
        user_info, client = self.verify_authorization_request(self.client_store, request)
        return user_info, client

    def verify_authorization_request(self, client_store, request):
        client_id = require(request.form, 'client_id', GrantError('invalid_request',
                            'client_id parameter is missing'))
        auth_code = require(request.form, 'code', GrantError('invalid_request',
                            'code parameter is missing'))

        auth_request = authorization_requests.get(auth_code)
        if auth_request is None:
            raise GrantError('invalid_request', 'authorization request not found')

        if auth_request['client_id'] != client_id:
            raise GrantError('invalid_request', 'client id mismatch')

        if self.is_expired(auth_request):
            raise GrantError('invalid_request', 'auth code is expired')

        client = client_store.get(client_id)
        if not client:
            raise GrantError('invalid_request', 'unknown client')

        self.verify_client_credentials(client, request)
        return auth_request, client

    @staticmethod
    def is_expired(auth_request):
        now = int(time.time())
        return now > int(auth_request['issued_at']) + FIVEMINUTES


class RefreshTokenGrant(Grant):
    """
      Validates refresh token grant.
      https://tools.ietf.org/html/rfc6749#section-6
    """
    def __init__(self, client_store):
        super().__init__(client_store)

    def validate(self, request):
        user_info, client = self.verify_refresh_token(self.client_store, request)
        return user_info, client

    def verify_refresh_token(self, client_store, request):
        refresh_token = require(request.form, 'refresh_token', GrantError('invalid_request',
                                'refresh_token is missing'))
        user_info = refresh_token_store.get(refresh_token)
        if not user_info:
            raise GrantError('invalid_grant', 'unknown refresh token')

        client_id = user_info['client_id']
        client = client_store.get(client_id)
        if not client:
            raise GrantError('invalid_request', 'unknown client')

        self.verify_client_credentials(client, request)

        return user_info, client


class ClientCredentialsGrant(Grant):
    """
      Validates client credentials grant.
      https://tools.ietf.org/html/rfc6749#section-4.4
    """
    def __init__(self, client_store):
        super().__init__(client_store)

    def validate(self, request):
        client_id, _ = self.extract_credentials(request)
        client = self.client_store.get(client_id)
        if not client:
            raise GrantError('invalid_request', 'unknown client')
        self.verify_client_credentials(client, request)
        user_info = {
            'id': client_id,
            'scope': self.verify_scopes(request.form.get('scope'), client)
        }
        return user_info, client

    def verify_scopes(self, scopes, client):
        allowed_scopes = set(client['scope'].split(' '))
        requested_scopes = allowed_scopes if scopes is None else set(scopes.split(' '))

        if not requested_scopes.issubset(allowed_scopes):
            raise GrantError('invalid_scope', 'One or more scopes are invalid')
        return ' '.join(requested_scopes)
