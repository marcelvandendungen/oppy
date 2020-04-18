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
        audience = 'https://localhost:5000/' if 'openid' in principal['scope'] else 'urn:my_service'
        token = self.issue_access_token(principal, audience)
        payload = {
            'access_token': token.decode("utf-8"),
            'token_type': 'Bearer',
            'expires_in': ONE_HOUR
        }
        if not client.is_public():
            payload['refresh_token'] = self.create_refresh_token(client['client_id'], principal)

        if 'code' in principal:
            authorization_requests.pop(principal['code'])

        if 'openid' in principal['scope']:
            payload['id_token'] = self.generate_token(principal,
                                                      self.private_key,
                                                      {'aud': client['client_id'],
                                                       'name': principal['name']}).decode("utf-8")

        return payload

    def validate(self, request):
        self.grant_type = require(request.form, 'grant_type', TokenRequestError('invalid_request',
                                  'grant_type parameter is missing'))

        if self.unsupported(self.grant_type):
            raise TokenRequestError('invalid_request', 'grant_type not supported')

        grant = handlers[self.grant_type]
        principal, client = grant(self.client_store).validate(request)
        return principal, client

    def issue_access_token(self, principal, audience):
        token = self.generate_token(principal, self.private_key, {'aud': audience})
        return token

    def generate_token(self, auth_request, private_key, add_claims):
        now = int(time.time())
        claims = {
            'sub': auth_request['id'],
            'iss': self.issuer,
            'iat': now,
            'nbf': now,
            'exp': now + ONE_HOUR,
            'scope': auth_request['scope']
        }

        claims.update(add_claims)

        token = jwt.encode(claims, private_key, algorithm='RS256')
        return token

    def create_refresh_token(self, client_id, auth_request):
        now = int(time.time())
        refresh_token = crypto.generate_refresh_token()

        payload = {
            'client_id': client_id,
            'expires': now + ONE_WEEK,
            'id': auth_request['id'],
            'scope': auth_request['scope']
        }

        if 'opendid' in auth_request['scope']:
            payload['name'] = auth_request['name']

        refresh_token_store.add(refresh_token, payload)

        return refresh_token

    @staticmethod
    def unsupported(grant_type):
        return grant_type not in handlers.keys()
