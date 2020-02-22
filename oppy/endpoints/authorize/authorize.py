import logging

from flask import Blueprint, request, make_response, render_template, redirect
from oppy.model.authorize_request import AuthorizeRequest, AuthorizeRequestError

logger = logging.getLogger('authorize')
logger.setLevel(logging.INFO)
logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)

def create_blueprint(testing, clients):
    authorize_bp = Blueprint('authorize_bp', __name__, template_folder='templates')

    @authorize_bp.route('/authorize', methods=["GET", "POST"])
    def authorize():
        if request.method == 'GET':
            return process_authorization_request(clients)
        else:
            return process_authentication_request(clients)

    return authorize_bp


def process_authorization_request(clients):
    # checks parameters and authenticates the resource owner
    try:
        auth_req = AuthorizeRequest.from_request_parameters(request.args)
        return make_response(render_template('login.html', req=auth_req.process(clients)))
    except AuthorizeRequestError as ex:
        return generate_error_response(ex)

def process_authentication_request(clients):
    # check credentials and other required form variables
    # issue code if all correct
    auth_req = AuthorizeRequest.from_form_variables(request.form)
    return auth_req.issue_code()

def generate_error_response(ex):
    logger.error(ex)

    if ex.http_code == 302:
        return redirect("/?error=something", code=302)

    return "Error occurred", ex.http_code
