import logging
from urllib.parse import urlencode

from flask import Blueprint, request, make_response, render_template, redirect
from provider.model.authorize_request import AuthorizeRequest, BadAuthorizeRequestError, AuthorizeRequestError

logger = logging.getLogger('authorize')
logger.setLevel(logging.INFO)
logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)


def create_blueprint(client_store):
    authorize_bp = Blueprint('authorize_bp', __name__, template_folder='templates',
                             static_folder='static', static_url_path='/static')

    @authorize_bp.route('/authorize', methods=["GET", "POST"])
    def authorize():
        try:
            if request.method == 'GET':
                return process_authorization_request(client_store)
            else:
                return process_authentication_request(client_store)

        except BadAuthorizeRequestError as ex:
            logger.error(ex)
            return "Error occurred: " + ex.error_description, 400
        except AuthorizeRequestError as ex:
            logger.error(ex)
            query_params = vars(ex)
            return redirect('/?' + urlencode(query_params), code=302)

    return authorize_bp


def process_authorization_request(client_store):
    """
    Processes GET /authorize endpoint, verifies query paramters, returns login page if all
    is correct
    """
    authorize_request = AuthorizeRequest.from_dictionary(request.args).validate(client_store)
    return make_response(render_template('login.html', req=authorize_request))


def process_authentication_request(client_store):
    """
    Processes POST /authorize endpoint, verifies posted credentials and other form variables,
    issues authorization code if all is correct
    """
    authorize_request = AuthorizeRequest.from_dictionary(request.form).process(client_store)
    return redirect(authorize_request.redirection_url())
