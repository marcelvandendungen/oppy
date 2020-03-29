import base64
import time
import jwt
import logging
from flask import Blueprint, request, make_response
from provider.model.authorization_request_store import authorization_requests
from provider.model.crypto import require
from provider.model import crypto


WEEK = 7 * 24 * 60 * 60
FIVEMINUTES = 5 * 60

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
                user_info, client = verify_refresh_token(client_store)
                client_id = user_info['client_id']
            elif grant_type == 'client_credentials':
                client_id, _ = extract_credentials()
                client = client_store.get(client_id)
                if not client:
                    raise TokenRequestError('invalid_request', 'unknown client')
                verify_client_credentials(client)
                user_info = {
                    'id': client_id
                }
            else:
                assert grant_type == 'authorization_code'
                user_info, client = verify_authorization_request(client_store)
                client_id = client['client_id']

            token = generate_token(user_info, keypair[0])

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
        return grant_type not in ('authorization_code', 'refresh_token', 'client_credentials')

    def generate_token(auth_request, private_key):
        now = int(time.time())
        claims = {
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


def verify_authorization_request(client_store):
    client_id = require(request.form, 'client_id', TokenRequestError('invalid_request',
                        'client_id parameter is missing'))
    auth_code = require(request.form, 'code', TokenRequestError('invalid_request',
                        'code parameter is missing'))

    auth_request = authorization_requests.get(auth_code)
    if auth_request is None:
        raise TokenRequestError('invalid_request', 'authorization request not found')

    if auth_request['client_id'] != client_id:
        raise TokenRequestError('invalid_request', 'client id mismatch')

    if is_expired(auth_request):
        raise TokenRequestError('invalid_request', 'auth code is expired')

    client = client_store.get(client_id)
    if not client:
        raise TokenRequestError('invalid_request', 'unknown client')

    verify_client_credentials(client)
    return auth_request, client


def is_expired(auth_request):
    now = int(time.time())
    return now > int(auth_request['issued_at']) + FIVEMINUTES


def create_refresh_token(client_id, auth_request):
    now = int(time.time())
    refresh_token = crypto.generate_refresh_token()
    refresh_tokens[refresh_token] = {
        'client_id': client_id,
        'expires': now + WEEK,
        'id': str(auth_request['id'])
    }
    return refresh_token


def verify_refresh_token(client_store):
    refresh_token = require(request.form, 'refresh_token', TokenRequestError('invalid_request',
                            'refresh_token is missing'))
    user_info = refresh_tokens.get(refresh_token)
    if not user_info:
        raise TokenRequestError('invalid_grant', 'unknown refresh token')

    client_id = user_info['client_id']
    client = client_store.get(client_id)
    if not client:
        raise TokenRequestError('invalid_request', 'unknown client')

    verify_client_credentials(client)

    return user_info, client


def verify_client_credentials(client):
    if client['token_endpoint_auth_method'] == 'client_secret_basic':
        id, secret = extract_credentials()
        if id != client['client_id']:
            raise TokenRequestError('invalid_request', 'Invalid client id')
        if secret != client['client_secret']:
            raise TokenRequestError('invalid_request', 'Incorrect client secret')


def extract_credentials():
    try:
        if 'Authorization' in request.headers:
            return extract_basic_credentials(request.headers['Authorization'])
        else:
            return extract_post_credentials()
    except Exception as ex:
        logger.error(str(ex))   # log exception and raise TokenRequestError

    raise TokenRequestError('invalid_request', 'Error verifying client credentials')


def extract_basic_credentials(authorization_header):
    if not authorization_header.startswith('Basic '):
        raise TokenRequestError('invalid_request', 'not basic auth')
    encoded = authorization_header[6:]
    raw = base64.b64decode(encoded.encode('utf-8')).decode('utf-8')
    client_id, client_secret = raw.split(':')
    return client_id, client_secret


def extract_post_credentials():
    client_id = request.form['client_id']
    client_secret = request.form['client_secret']
    return client_id, client_secret
