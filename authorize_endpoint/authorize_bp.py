from flask import Blueprint

authorize_bp = Blueprint('authorize_bp', __name__)

@authorize_bp.route('/authorize')
def authorize():
    return "authorize endpoint"
