from flask import Blueprint, request
from oppy.model.authorize_request import AuthorizeRequest

authorize_bp = Blueprint('authorize_bp', __name__)

@authorize_bp.route('/authorize', methods=["GET", "POST"])
def authorize():
    if request.method == 'GET':
        # checks parameters and authenticates the resource owner
        return AuthorizeRequest().process(request.args)
    else:
        return AuthorizeRequest().issue(request.form)
