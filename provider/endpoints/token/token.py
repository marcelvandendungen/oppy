from provider.model.grants import AuthorizationCodeGrant, ClientCredentialsGrant, GrantError, RefreshTokenGrant
import time
import jwt
from flask import Blueprint, request, make_response
from provider.model.refresh_token_store import refresh_token_store
from provider.model.util import require
from provider.model import crypto
from provider.model.util import init_logging

ONE_HOUR = 60 * 60
ONE_WEEK = 7 * 24 * ONE_HOUR


logger = init_logging(__name__)

handlers = {
    'authorization_code': AuthorizationCodeGrant,
    'refresh_token': RefreshTokenGrant,
    'client_credentials': ClientCredentialsGrant
}


class TokenRequestError(RuntimeError):
    pass


def create_blueprint(client_store, keypair):
    token_bp = Blueprint('token_bp', __name__)

    @token_bp.route('/token', methods=["POST"])
    def token():

        try:
            grant_type = require(request.form, 'grant_type', TokenRequestError('invalid_request',
                                 'grant_type parameter is missing'))

            if unsupported(grant_type):
                raise TokenRequestError('invalid_request', 'grant_type not supported')

            grant = handlers[grant_type]
            principal, client = grant(client_store).validate(request)

            token = generate_token(principal, keypair[0])

            logger.info(str(token))
            resp = {
                'access_token': token.decode("utf-8"),
                'token_type': 'Bearer',
                'expires_in': ONE_HOUR
            }

            if not client.is_public():
                resp['refresh_token'] = create_refresh_token(client['client_id'], principal)

            return resp, 200
        except KeyError as ex:
            raise TokenRequestError('invalid_request', ex)
        except (TokenRequestError, GrantError) as ex:
            logger.error(ex)
            payload = {
                'error': ex.args[0],
                'error_description': ex.args[1]
            }
            response = make_response(payload, 200)
            response.headers['Content-Type'] = 'application/json'
            return response, 400

    def unsupported(grant_type):
        return grant_type not in ('authorization_code', 'refresh_token', 'client_credentials')

    def generate_token(auth_request, private_key):
        now = int(time.time())
        claims = {
            'sub': str(auth_request['id']),
            'iss': 'https://localhost:5000',
            'aud': 'urn:my_service',
            'iat': now,
            'nbf': now,
            'exp': now + ONE_HOUR,
            'scope': 'read write'
        }

        token = jwt.encode(claims, private_key, algorithm='RS256')
        return token

    return token_bp


def create_refresh_token(client_id, auth_request):
    now = int(time.time())
    refresh_token = crypto.generate_refresh_token()
    refresh_token_store.add(refresh_token, {
        'client_id': client_id,
        'expires': now + ONE_WEEK,
        'id': str(auth_request['id'])
    })
    return refresh_token
