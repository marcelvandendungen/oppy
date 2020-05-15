from contextlib import suppress
import itertools
from provider.model.store.user_store import user_store
from provider.model.oauth2.authorize_request import AuthorizeRequest
from flask import Blueprint, request, redirect, make_response, render_template
from provider.model.store.authorization_request_store import authorization_requests
from provider.model.store.consent_store import consent_store
from util import init_logging

logger = init_logging(__name__)


def create_blueprint(client_store):
    consent_bp = Blueprint('consent_bp', __name__)

    @consent_bp.route('/consent', methods=["POST"])
    def consent():
        try:
            return process_consent_request(client_store)

        except Exception as ex:
            logger.exception("Exception occurred")
            return "Error occurred: " + str(ex), 400

    return consent_bp


def process_consent_request(client_store):
    """
      Processes POST /consent endpoint, verifies posted form variables,
      issues authorization code if all is correct
    """
    try:
        # get id from form vars
        id = request.form['id']
        # look up auth code by id
        auth_code = consent_store.get(id)
        # look up auth request by code
        authorize_request = AuthorizeRequest.from_dictionary(authorization_requests.get(auth_code))
        # check if consent granted
        if request.form.get('approve'):
            # store consent in user store
            user_store.update_scopes(authorize_request.username, get_scopes(request.form))
            if authorize_request.form_post_response:
                return make_response(render_template('form_post.html', redirect_uri=authorize_request.redirect_uri,
                                                     state=authorize_request.state, code=authorize_request.code))

            # redirect to client with query parameters
            return redirect(authorize_request.redirection_url())
        else:
            # denied
            return redirect(authorize_request.redirect_error('access_denied'))
    except Exception as ex:
        logger.exception("Exception occurred")
        return "Error occurred: " + str(ex), 500


def scope_values(parameters):
    """
      Returns values from parameters dictionary for all keys like 'scope0, scope1...'
    """
    with suppress(KeyError):
        names = (f'scopes{index}' for index in itertools.count(start=0, step=1))
        for name in names:
            yield parameters[name]


def get_scopes(parameters):
    """
      Extract scope values from parameters dictionary as space separated string
    """
    scopes = [value for value in scope_values(parameters)]
    return ' '.join(scopes)
