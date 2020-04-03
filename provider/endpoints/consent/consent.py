from flask import Blueprint, request, redirect
from provider.model.authorization_request_store import authorization_requests
from provider.model.consent_store import consent_store
from util import init_logging

logger = init_logging(__name__)


def create_blueprint(client_store):
    consent_bp = Blueprint('consent_bp', __name__)

    @consent_bp.route('/consent', methods=["POST"])
    def consent():
        try:
            return process_consent_request(client_store)

        except Exception as ex:
            logger.error(ex)
            return "Error occurred: " + str(ex), 400

    return consent_bp


def process_consent_request(client_store):
    """
      Processes POST /consent endpoint, verifies posted form variables,
      issues authorization code if all is correct
    """
    # get id from form vars
    id = request.form_vars['id']
    # look up auth code by id
    auth_code = consent_store.get(id)
    # look up auth request by code
    authorize_request = authorization_requests.pop(auth_code)
    # redirect to client with query parameters
    return redirect(authorize_request.redirection_url())
