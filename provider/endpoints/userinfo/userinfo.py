from util import init_logging
from provider.model.store.user_store import user_store
from oidcpy.authorize import authorize

from flask import Blueprint, request, jsonify, make_response

logger = init_logging(__name__)

AUDIENCE = 'https://localhost:5000/'


def create_blueprint(config):
    userinfo_bp = Blueprint('userinfo_blueprint', __name__)

    @userinfo_bp.route('/userinfo', methods=["GET"])
    @authorize(audience=AUDIENCE, scopes='openid')
    def userinfo():
        subject = get_subject_from_token()
        user = user_store.get_by_id(subject)
        payload = {
            'sub': subject,
            'name': user['name']
        }
        if 'email' in user['consented_scopes'] and 'email' in user:
            payload['email'] = user['email']
        if 'roles' in user['consented_scopes'] and 'roles' in user:
            payload['roles'] = user['roles']

        resp = make_response(jsonify(payload))
        resp.headers['Content-Type'] = 'application/json'
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Methods'] = 'GET'
        resp.headers['Access-Control-Allow-Headers'] = 'Authorization'
        return resp, 200

    def get_subject_from_token():
        claims = request.view_args['claims']
        subject = claims['sub']    # subject claim from access token
        return subject

    return userinfo_bp
