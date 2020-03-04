import time
import jwt
import logging
from flask import Blueprint, request
from oppy.model.authorization_request_store import authorization_requests
from oppy.model.crypto import require


logger = logging.getLogger('token')
logger.setLevel(logging.INFO)
logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)


class TokenRequestError(RuntimeError):
    pass


def create_blueprint(clients):
    token_bp = Blueprint('token_bp', __name__)

    @token_bp.route('/token', methods=["POST"])
    def token():

        try:

            grant_type = require(request.form, 'grant_type', TokenRequestError('invalid_request', 'grant_type parameter is missing'))
            client_id = require(request.form, 'client_id', TokenRequestError('invalid_request', 'client_id parameter is missing'))

            if unsupported(grant_type):
                raise TokenRequestError('invalid_request', 'grant_type not supported')

            auth_code = require(request.form, 'code', TokenRequestError('invalid_request', 'code parameter is missing'))

            auth_request = authorization_requests.get(auth_code)
            if auth_request is None:
                raise TokenRequestError('invalid_request', 'authorization request not found')

            if auth_request['client_id'] != client_id:
                raise TokenRequestError('invalid_request', 'client id mismatch')

            token = generate_token(auth_request)
            logger.info(str(token))
            resp = {
                'access_token': token.decode("utf-8"),
                'token_type': 'Bearer',
                'expires_in': 3600
            }
            return resp, 200
        except KeyError as ex:
            raise TokenRequestError('invalid_request', ex)
        except TokenRequestError as ex:
            logger.error(ex)
            return "Error occurred: " + ' - '.join(ex.args), 400

    def unsupported(grant_type):
        return grant_type not in ('authorization_code', )

    def generate_token(auth_request):
        secret = '2d!SXV32Adf40-=2`c'
        now = int(time.time())
        claims = {
            'userid': str(auth_request['id']),
            'username': auth_request['username'],
            'aud': 'urn:my_service',
            'iat': now,
            'nbf': now,
            'exp': now + 3600
        }

        token = jwt.encode(claims, secret, algorithm='HS256')

        return token

    return token_bp
