from provider.model.registration_request import RegistrationRequest, RegistrationError
from util import init_logging

from flask import Blueprint, request, jsonify, make_response

logger = init_logging(__name__)


def create_blueprint(clients):
    register_bp = Blueprint('register_blueprint', __name__)

    @register_bp.route('/register', methods=["POST"])
    def register():
        try:
            registration_request = RegistrationRequest.from_dictionary(request.json)

            payload = jsonify(registration_request.client)
            logger.info(str(registration_request.client))
            resp = make_response(payload)
            resp.headers['Content-Type'] = 'application/json'
            return resp, 201
        except RegistrationError as ex:
            logger.error(str(ex))
            return jsonify({
                'error': ex.code,
                'error_description': str(ex)
            }), 400
            # return "Error occurred: " + ' - '.join(ex.args), 400

    return register_bp
