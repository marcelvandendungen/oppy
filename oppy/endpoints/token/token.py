from flask import Blueprint

token_bp = Blueprint('token_bp', __name__)

@token_bp.route('/token')
def token():
    return "token endpoint"
