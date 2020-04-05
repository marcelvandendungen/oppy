import traceback
import sys
from flask import Blueprint, request, make_response
from provider.model.token_request import TokenRequest, TokenRequestError
from provider.model.grants import GrantError
from util import init_logging


logger = init_logging(__name__)


def create_blueprint(client_store, private_key, config):
    token_bp = Blueprint('token_bp', __name__)

    @token_bp.route('/token', methods=["POST"])
    def token():

        try:
            token_request = TokenRequest(client_store, private_key, config['endpoints']['issuer'])
            resp = token_request.create_response(request)

            logger.info(str(resp))

            return resp, 200
        except KeyError as ex:
            raise TokenRequestError('invalid_request', ex)
        except (TokenRequestError, GrantError) as ex:
            logger.error(ex)
            traceback.print_exc(file=sys.stdout)
            payload = {
                'error': ex.args[0],
                'error_description': ex.args[1]
            }
            response = make_response(payload, 200)
            response.headers['Content-Type'] = 'application/json'
            return response, 400

    return token_bp
