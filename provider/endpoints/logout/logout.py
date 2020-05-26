import jwt
from util import init_logging
from provider.model.store.client_store import client_store

from flask import Blueprint, request, make_response, render_template

logger = init_logging(__name__)


def create_blueprint(config, public_key):
    logout_bp = Blueprint('logout_blueprint', __name__)

    @logout_bp.route('/logout', methods=["GET"])
    def logout():
        id_token = request.args.get('id_token_hint')
        state = request.args.get('state')
        if id_token:
            # fetch audience from claims before verifying the token
            claims = jwt.decode(str.encode(id_token), public_key, algorithms='RS256', verify=False)
            client_id = claims['aud']
            claims = jwt.decode(str.encode(id_token), public_key, audience=client_id, algorithms='RS256')
        else:
            session_cookie = request.cookies.get('session')
            claims = jwt.decode(str.encode(session_cookie), public_key, audience='https://localhost:5000',
                                algorithms='RS256')
            client_id = claims['client_id']
        client = client_store.get(client_id)
        post_logout_uri = request.args.get('post_logout_redirect_uri')
        if not post_logout_uri or post_logout_uri not in client['post_logout_redirect_uris']:
            post_logout_uri = ''

        resp = make_response(render_template('logout.html', uri=client['frontchannel_logout_uri'],
                                             post_logout_uri=post_logout_uri, state=state))
        resp.set_cookie('session', '', expires=0)
        return resp

    return logout_bp
