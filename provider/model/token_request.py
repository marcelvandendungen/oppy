import jwt
import time
from util import require

from provider.model.grants import AuthorizationCodeGrant, ClientCredentialsGrant, RefreshTokenGrant
from provider.model.authorization_request_store import authorization_requests
from provider.model.refresh_token_store import refresh_token_store
from provider.model import crypto


ONE_HOUR = 60 * 60
ONE_WEEK = 7 * 24 * ONE_HOUR

handlers = {
    'authorization_code': AuthorizationCodeGrant,
    'refresh_token': RefreshTokenGrant,
    'client_credentials': ClientCredentialsGrant
}


class TokenRequestError(Exception):
    pass


class TokenRequest:

    def __init__(self, client_store, private_key, issuer):
        self.client_store = client_store
        self.private_key = private_key
        self.issuer = issuer

    def create_response(self, request):
        principal, client = self.validate(request)
        token = self.issue_access_token(principal)
        payload = {
            'access_token': token.decode("utf-8"),
            'token_type': 'Bearer',
            'expires_in': ONE_HOUR
        }
        if not client.is_public():
            payload['refresh_token'] = self.create_refresh_token(client['client_id'], principal)

        if 'code' in principal:
            authorization_requests.pop(principal['code'])

        return payload

    def validate(self, request):
        self.grant_type = require(request.form, 'grant_type', TokenRequestError('invalid_request',
                                  'grant_type parameter is missing'))

        if self.unsupported(self.grant_type):
            raise TokenRequestError('invalid_request', 'grant_type not supported')

        grant = handlers[self.grant_type]
        principal, client = grant(self.client_store).validate(request)
        return principal, client

    def issue_access_token(self, principal):
        token = self.generate_token(principal, self.private_key)
        return token

    def generate_token(self, auth_request, private_key):
        now = int(time.time())
        claims = {
            'sub': str(auth_request['id']),
            'iss': self.issuer,
            'aud': 'urn:my_service',
            'iat': now,
            'nbf': now,
            'exp': now + ONE_HOUR,
            'scope': auth_request['scope']
        }

        token = jwt.encode(claims, private_key, algorithm='RS256')
        return token

    def create_refresh_token(self, client_id, auth_request):
        now = int(time.time())
        refresh_token = crypto.generate_refresh_token()
        refresh_token_store.add(refresh_token, {
            'client_id': client_id,
            'expires': now + ONE_WEEK,
            'id': str(auth_request['id']),
            'scope': auth_request['scope']
        })
        return refresh_token

    @staticmethod
    def unsupported(grant_type):
        return grant_type not in handlers.keys()
