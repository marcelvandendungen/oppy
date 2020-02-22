from flask import Blueprint

def create_blueprint(testing, clients):
    token_bp = Blueprint('token_bp', __name__)

    @token_bp.route('/token')
    def token():
        return "token endpoint"

    return token_bp
