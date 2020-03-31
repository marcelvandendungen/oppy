from flask import Blueprint, make_response
from jwcrypto import jwk

from provider.model.util import init_logging

logger = init_logging(__name__)


def create_blueprint():
    jwk_bp = Blueprint('jwk_blueprint', __name__, template_folder='templates')

    @jwk_bp.route('/jwk')
    def get_jwk():
        with open("public.pem", "rb") as f:
            key = jwk.JWK.from_pem(f.read())
            response = make_response(key.export(private_key=False), 200)
            response.headers['Content-Type'] = 'application/json'
            return response

    return jwk_bp
