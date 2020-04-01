from util import init_logging

from flask import Blueprint, jsonify, make_response

logger = init_logging(__name__)


def create_blueprint(config):
    metadata_bp = Blueprint('metadata_blueprint', __name__)

    @metadata_bp.route('/.well-known/openid-configuration', methods=["GET"])
    def metadata():
        issuer = config['endpoints']['issuer']
        payload = {
            'issuer': issuer,
            'authorization_endpoint': issuer + config['endpoints']['authorize'],
            'token_endpoint': issuer + config['endpoints']['token'],
            'userinfo_endpoint': issuer + config['endpoints']['userinfo'],
            'jwks_uri': issuer + config['endpoints']['jwks'],
            'registration_endpoint': issuer + config['endpoints']['registration'],
            'scopes_supported': config['capabilities']['scopes_supported'],
            'response_types_supported': config['capabilities']['response_types_supported'],
            'grant_types_supported': config['capabilities']['grant_types_supported'],
            'claims_supported': config['capabilities']['claims_supported']
        }
        resp = make_response(jsonify(payload))
        resp.headers['Content-Type'] = 'application/json'
        return resp, 200

    return metadata_bp
