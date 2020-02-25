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
        if request.method == 'GET':
            return process_authorization_request(clients)
        else:
            return process_authentication_request(clients)

    return authorize_bp


def process_authorization_request(clients):
    # checks parameters and authenticates the resource owner
    try:
        authorize_request = AuthorizeRequest.from_dictionary(request.args).validate(clients)
        return make_response(render_template('login.html', req=authorize_request))
    except BadAuthorizeRequestError as ex:
        logger.error(ex)
        return "Error occurred: " + ex.error_description, 400
    except AuthorizeRequestError as ex:
        logger.error(ex)
        query_params = vars(ex)
        return redirect('/?' + urlencode(query_params), code=302)


def process_authentication_request(clients):
    # check credentials and other required form variables
    # issue code if all correct
    auth_req = AuthorizeRequest.from_dictionary(request.form)
    return redirect(auth_req.redirection_url(clients))
