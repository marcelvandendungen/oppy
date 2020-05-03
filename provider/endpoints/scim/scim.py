from provider.model.scim_user import ScimUser, ScimError
from provider.model.scim_group import ScimGroup
from provider.model.user_store import user_store
from provider.model.group_store import group_store
from provider.model.authorize import authorize

from flask import Blueprint, request, make_response, jsonify, abort
from util import init_logging

logger = init_logging(__name__)
AUDIENCE = 'https://localhost:5000/'
SCIM_PATH = '/scim/v2/'
USER_PATH = SCIM_PATH + 'Users'
GROUP_PATH = SCIM_PATH + 'Groups'


def create_blueprint(config):
    scim_bp = Blueprint('scim_bp', __name__, template_folder='templates')

    @scim_bp.route(USER_PATH + '/<string:user_id>', methods=['GET'])
    @authorize(audience=AUDIENCE, scopes='get_user')
    def get_user(user_id):
        try:
            user = user_store.get_by_id(user_id)
            if not user:
                return 404, 'Not found'
            scim_user = ScimUser.create_from(user, config['endpoints']['issuer'])
            return make_scim_response(200, dict(scim_user.items()), get_etag(scim_user))
        except ScimError as ex:
            scim_abort(ex)

    @scim_bp.route(USER_PATH, methods=["POST"])
    @authorize(audience=AUDIENCE, scopes='create_user')
    def create_user():
        try:
            user = ScimUser.create_from(request.json, config['endpoints']['issuer'])
            user_store.add(user)
            return make_scim_response(201, dict(user.items()), get_etag(user))

        except ScimError as ex:
            scim_abort(ex)
        except Exception as ex:
            logger.exception("Exception occurred")
            return "Error occurred: " + ex.error_description, 400

    @scim_bp.route(USER_PATH, methods=["GET"])
    @authorize(audience=AUDIENCE, scopes='get_user')
    def list_users():
        try:
            users = user_store.list()
            return make_scim_list_response(users, 1, len(users))

        except ScimError as ex:
            scim_abort(ex)
        except Exception as ex:
            logger.exception("Exception occurred")
            return "Error occurred: " + ex.error_description, 400

    @scim_bp.route(GROUP_PATH + '/<string:group_id>', methods=['GET'])
    @authorize(audience=AUDIENCE, scopes='get_group')
    def get_group(group_id):
        try:
            group = group_store.get_by_id(group_id)
            if not group:
                return 404, 'Not found'
            scim_group = ScimGroup.create_from(group, config['endpoints']['issuer'])
            return make_scim_response(200, dict(scim_group.items()), group.get_etag())
        except ScimError as ex:
            scim_abort(ex)

    @scim_bp.route(GROUP_PATH, methods=["POST"])
    @authorize(audience=AUDIENCE, scopes='create_group')
    def create_group():
        try:
            group = ScimGroup.create_from(request.json, config['endpoints']['issuer'])
            group_store.add(group)
            return make_scim_response(201, dict(group.items()), group.get_etag())

        except ScimError as ex:
            scim_abort(ex)
        except Exception as ex:
            logger.exception("Exception occurred")
            return "Error occurred: " + ex.error_description, 400

    def make_scim_response(code, data, etag=None):
        resp = make_response(jsonify(data))
        resp.headers['Content-Type'] = 'application/scim+json'
        if etag:
            resp.headers['ETag'] = etag
        return resp, code

    def make_scim_list_response(data, start_index, count):
        response = {
            'schemas': ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
            'totalResults': len(data),
            'Resources': data,
            'startIndex': start_index,
            'itemsPerPage': count
        }
        return make_scim_response(200, response)

    def scim_abort(ex):
        abort(make_response(jsonify(create_error_payload(ex.status, ex.detail, ex.scim_type)), ex.status))

    def create_error_payload(status, detail, scim_type=None):
        data = {
            'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
            'status': str(status),
            'detail': detail
        }
        if scim_type:
            data['scimType'] = scim_type

        return data

    def get_etag(user_dict):
        return ScimUser.get_version(user_dict['meta']['created'], user_dict['meta']['modified'])

    return scim_bp
