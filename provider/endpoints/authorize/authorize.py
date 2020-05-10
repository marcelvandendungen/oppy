from provider.model.store.consent_store import consent_store
from urllib.parse import urlencode

from flask import Blueprint, request, make_response, render_template, redirect
from provider.model.oauth2.authorize_request import AuthorizeRequest, BadAuthorizeRequestError, AuthorizeRequestError
from provider.model.oauth2.authorize_request import AuthenticationError
from util import init_logging
import jwt
import time

logger = init_logging(__name__)


def create_blueprint(client_store, public_key, private_key):
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

    def process_authorization_request(client_store):
        """
        Processes GET /authorize endpoint, verifies query paramters, returns login page if all
        is correct
        """
        authorize_request = AuthorizeRequest.from_dictionary(request.args).validate(client_store)
        session = authenticated_session(request.cookies.get('session'))
        if session:
            authorize_request = AuthorizeRequest.from_dictionary(request.args).process(client_store,
                                                                                       session=session)
            if not authorize_request.consent_given(authorize_request.scope):
                return show_consent_page(authorize_request, request.cookies.get('session'))
            return redirect(authorize_request.redirection_url())

        return make_response(render_template('login.html', req=authorize_request.__dict__))

    def process_authentication_request(client_store):
        """
        Processes POST /authorize endpoint, verifies posted credentials and other form variables,
        issues authorization code if all is correct and user has already given consent, displays
        consent page otherwise.
        """
        authorize_request = AuthorizeRequest.from_dictionary(request.form)

        try:
            authorize_request.process(client_store)
            session = create_session_token(authorize_request)
            logger.info("Added auth request for: " + authorize_request.code)
            if authorize_request.consent_given(authorize_request.scope):
                if authorize_request.form_post_response:
                    resp = make_response(render_template('form_post.html', redirect_uri=authorize_request.redirect_uri,
                                                         state=authorize_request.state, code=authorize_request.code))
                else:
                    resp = redirect(authorize_request.redirection_url())
                resp.set_cookie('session', session)
            else:
                return show_consent_page(authorize_request, session)

            return resp
        except AuthenticationError:
            logger.exception("Exception occurred")
            return make_response(render_template('login.html', req=authorize_request.__dict__, error=True))

    def create_session_token(principal):
        now = int(time.time())
        claims = {
            'id': principal.id,
            'username': principal.username,
            'consented_scopes': principal.consented_scopes,
            'aud': 'https://localhost:5000',
            'iat': now,
            'nbf': now,
            'exp': now + 3600,
            'name': principal.name
        }

        token = jwt.encode(claims, private_key, algorithm='RS256')
        return token

    def authenticated_session(token):
        try:
            if not token:
                logger.info("Session cookie not found")
                return None
            claims = jwt.decode(str.encode(token), public_key, audience='https://localhost:5000', algorithms='RS256')
            logger.info("Session cookie is valid")
            return claims
        except jwt.ExpiredSignatureError:
            logger.info("Session cookie expired")
            return None

    def show_consent_page(authorize_request, session):
        # store code by id
        client = client_store.get(authorize_request.client_id)
        id = consent_store.add(authorize_request.code)
        resp = make_response(render_template('consent.html',
                             client_name=client['name'],
                             scopes=authorize_request.scope.split(' '),
                             id=id, client_id=authorize_request.client_id,
                             state=authorize_request.state))
        resp.set_cookie('session', session)
        return resp

    return authorize_bp
