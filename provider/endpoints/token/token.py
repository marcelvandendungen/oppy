import time
import jwt
import logging
from flask import Blueprint, request, make_response
from provider.model.authorization_request_store import authorization_requests
from provider.model.crypto import require
from provider.model import crypto


WEEK = 7 * 24 * 60 * 60

logger = logging.getLogger('token')
logger.setLevel(logging.INFO)
logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)

refresh_tokens = {}


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

            if grant_type == 'refresh_token':
                refresh_token = require(request.form, 'refresh_token', TokenRequestError('invalid_request',
                                        'refresh_token is missing'))
                user_info = refresh_tokens.get(refresh_token)
                if not user_info:
                    raise TokenRequestError('invalid_grant', 'unknown refresh token')
                client_id = user_info['client_id']
                # TODO: verify client credentials and match client id againt info.client_id
            else:
                client_id = require(request.form, 'client_id', TokenRequestError('invalid_request',
                                    'client_id parameter is missing'))
                auth_code = require(request.form, 'code', TokenRequestError('invalid_request',
                                    'code parameter is missing'))

                auth_request = authorization_requests.get(auth_code)
                if auth_request is None:
                    raise TokenRequestError('invalid_request', 'authorization request not found')

                if auth_request['client_id'] != client_id:
                    raise TokenRequestError('invalid_request', 'client id mismatch')

                user_info = auth_request

            token = generate_token(user_info, keypair[0])

            client = client_store.get(client_id)
            if not client:
                raise TokenRequestError('invalid_request', 'unknown client')

            logger.info(str(token))
            resp = {
                'access_token': token.decode("utf-8"),
                'token_type': 'Bearer',
                'expires_in': 3600
            }

            if not client.is_public():
                resp['refresh_token'] = create_refresh_token(client_id, user_info)

            return resp, 200
        except KeyError as ex:
            raise TokenRequestError('invalid_request', ex)
        except TokenRequestError as ex:
            logger.error(ex)
            payload = {
                'error': ex.args[0],
                'error_description': ex.args[1]
            }
            response = make_response(payload, 200)
            response.headers['Content-Type'] = 'application/json'
            return response, 400

    def unsupported(grant_type):
        return grant_type not in ('authorization_code', 'refresh_token')

    def generate_token(auth_request, private_key):
        now = int(time.time())
        claims = {
            'username': auth_request['username'],
            'sub': str(auth_request['id']),
            'iss': 'https://localhost:5000',
            'aud': 'urn:my_service',
            'iat': now,
            'nbf': now,
            'exp': now + 3600,
            'scope': 'read write'
        }

        token = jwt.encode(claims, private_key, algorithm='RS256')

        return token

    return token_bp


def create_refresh_token(client_id, auth_request):
    now = int(time.time())
    refresh_token = crypto.generate_refresh_token()
    refresh_tokens[refresh_token] = {
        'client_id': client_id,
        'expires': now + WEEK,
        'username': auth_request['username'],
        'id': str(auth_request['id'])
    }
    return refresh_token
