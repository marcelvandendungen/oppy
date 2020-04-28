from provider.model.scim_user import ScimUser
from provider.model.user_store import user_store
from provider.model.authorize import authorize

from flask import Blueprint, request, make_response, jsonify
from util import init_logging

logger = init_logging(__name__)
AUDIENCE = 'scim_service'


def create_blueprint():
    scim_bp = Blueprint('scim_bp', __name__, template_folder='templates')

    @scim_bp.route('/scim/v2/User', methods=["POST"])
    @authorize(audience=AUDIENCE, scopes='create_user')
    def user():
        try:
            if request.method == 'GET':
                return get_user(request.args)
            elif request.method == 'POST':
                return create_user(request.form)

        except Exception as ex:
            logger.exception("Exception occurred: " + str(ex))
            return "Error occurred: " + ex.error_description, 400

    @scim_bp.route('/scim/v2/Users/<string:user_id>', methods=['GET'])
    @authorize(audience=AUDIENCE, scopes='get_user')
    def get_user(user_id):
        user = user_store.get_by_id(user_id)
        if not user:
            return 404, 'Not found'
        scim_user = ScimUser.create_from(user, request.host_url)
        return make_scim_response(200, dict(scim_user.items()), user.get_etag())

    def create_user(parameters):
        user = ScimUser.create_from(request.json, request.host_url)
        user_store.add(user)
        return make_scim_response(201, dict(user.items()), user.get_etag())

    def make_scim_response(code, data, etag=None):
        resp = make_response(jsonify(data))
        resp.headers['Content-Type'] = 'application/scim+json'
        if etag:
            resp.headers['ETag'] = etag
        return resp, code

    return scim_bp
