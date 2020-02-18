import logging

from flask import Blueprint, request, make_response, render_template
from oppy.model.authorize_request import AuthorizeRequest, AuthorizeRequestError

authorize_bp = Blueprint('authorize_bp', __name__, template_folder='templates')
logger = logging.getLogger('authorize')
logger.setLevel(logging.INFO)
logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)

# default test clients
clients = [{
    'client_id': 'confidential_client',
    'redirect_uris': ['http://localhost:5001/cb'], # must be absolute URL, may contain query params, must not contain fragment
    'public': False
}, 
{
    'client_id': 'public_client',
    'redirect_uris': ['http://localhost:5002/cb'],
    'public': True
}]


@authorize_bp.route('/authorize', methods=["GET", "POST"])
def authorize():
    if request.method == 'GET':
        return process_authorization_request()
    else:
        return process_authentication_request()

def process_authorization_request():
    # checks parameters and authenticates the resource owner
    try:
        auth_req = AuthorizeRequest.from_request_parameters(request.args)
        return make_response(render_template('login.html', req=auth_req.process(clients)))
    except AuthorizeRequestError as ex:
        return generate_error_response(ex)

def process_authentication_request():
    # check credentials and other required form variables
    # issue code if all correct
    auth_req = AuthorizeRequest.from_form_variables(request.form)
    return auth_req.issue_code()

def generate_error_response(ex):
    logger.error(ex)
    return "Error occurred", ex.error_code
