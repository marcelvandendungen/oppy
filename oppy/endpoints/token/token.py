from flask import Blueprint


def create_blueprint(clients):
    token_bp = Blueprint('token_bp', __name__)

    @token_bp.route('/token')
    def token():
        return "token endpoint"

    return token_bp
