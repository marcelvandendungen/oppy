from provider.model.consent_store import consent_store
from urllib.parse import urlencode

from flask import Blueprint, request, make_response, render_template, redirect
from provider.model.authorize_request import AuthorizeRequest, BadAuthorizeRequestError, AuthorizeRequestError
from util import init_logging

logger = init_logging(__name__)


def create_blueprint(client_store):
    authorize_bp = Blueprint('authorize_bp', __name__, template_folder='templates')

    @authorize_bp.route('/authorize', methods=["GET", "POST"])
    def authorize():
        try:
            if request.method == 'GET':
                return process_authorization_request(client_store)
            else:
                return process_authentication_request(client_store)

        except BadAuthorizeRequestError as ex:
            logger.exception("Exception occurred")
            return "Error occurred: " + ex.error_description, 400
        except AuthorizeRequestError as ex:
            logger.exception("Exception occurred")
            query_params = vars(ex)
            return redirect('/?' + urlencode(query_params), code=302)

    return authorize_bp


def process_authorization_request(client_store):
    """
    Processes GET /authorize endpoint, verifies query paramters, returns login page if all
    is correct
    """
    authorize_request = AuthorizeRequest.from_dictionary(request.args).validate(client_store)
    return make_response(render_template('login.html', req=authorize_request.__dict__))


def process_authentication_request(client_store):
    """
    Processes POST /authorize endpoint, verifies posted credentials and other form variables,
    issues authorization code if all is correct and user has already given consent, displays
    consent page otherwise.
    """
    authorize_request = AuthorizeRequest.from_dictionary(request.form).process(client_store)
    logger.info("Added auth request for: " + authorize_request.code)
    if authorize_request.user_has_given_consent:
        return redirect(authorize_request.redirection_url())
    else:
        # store code by id
        client = client_store.get(authorize_request.client_id)
        id = consent_store.add(authorize_request.code)
        return render_template('consent.html', 
                               client_name=client['name'],
                               scopes=client.get('scope', '').split(' '),
                               id=id, client_id=authorize_request.client_id,
                               state=authorize_request.state)
