import logging

from flask import Blueprint, request, make_response, render_template, redirect
from oppy.model.authorize_request import AuthorizeRequest, BadAuthorizeRequestError, AuthorizeRequestError
from urllib.parse import urlencode

logger = logging.getLogger('authorize')
logger.setLevel(logging.INFO)
logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)


def create_blueprint(clients):
    authorize_bp = Blueprint('authorize_bp', __name__, template_folder='templates')

    @authorize_bp.route('/authorize', methods=["GET", "POST"])
    def authorize():
        try:
            if request.method == 'GET':
                return process_authorization_request(clients)
            else:
                return process_authentication_request(clients)

        except BadAuthorizeRequestError as ex:
            logger.error(ex)
            return "Error occurred: " + ex.error_description, 400
        except AuthorizeRequestError as ex:
            logger.error(ex)
            query_params = vars(ex)
            return redirect('/?' + urlencode(query_params), code=302)

    return authorize_bp


def process_authorization_request(clients):
    """
    Processes GET /authorize endpoint, verifies query paramters, returns login page if all
    is correct
    """
    # checks parameters and authenticates the resource owner
    authorize_request = AuthorizeRequest.from_dictionary(request.args).validate(clients)
    return make_response(render_template('login.html', req=authorize_request))


def process_authentication_request(clients):
    """
    Processes POST /authorize endpoint, verifies posted credentials and other form variables,
    issues authorization code if all is correct
    """
    authorize_request = AuthorizeRequest.from_dictionary(request.form)
    return redirect(authorize_request.redirection_url(clients))
