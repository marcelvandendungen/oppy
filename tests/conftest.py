import base64
from urllib.parse import urlsplit, parse_qsl
from provider.app import app, init
from provider.endpoints.scim.scim import USER_PATH, GROUP_PATH

import json
import pytest


class FixtureError(Exception):
    pass


@pytest.fixture(scope='session')
def test_client():

    init('provider/config.yml')

    testing_client = app.test_client()

    ctx = app.app_context()
    ctx.push()

    yield testing_client

    ctx.pop()


@pytest.fixture(scope='session')
def confidential_client(test_client):
    payload = {
        'grant_types': [
            'authorization_code'
        ],
        'redirect_uris': [
            'https://localhost:5001/cb',
            'https://localhost:5003/cb'
        ],
        'token_endpoint_auth_method': 'client_secret_basic',
        'name': 'confidential_client',
        'scope': "openid read write",
        "frontchannel_logout_uri": "https://localhost:5001/logout",
        "post_logout_redirect_uris": ["https://localhost:5001/logged_out"]
    }
    return register_client(test_client, payload)


@pytest.fixture(scope='session')
def public_client(test_client):
    payload = {
        'client_id': 'public_client',
        'redirect_uris': ['https://localhost:5002/cb'],
        'token_endpoint_auth_method': 'None',
        'name': 'public_client',
        'scope': "read write"
    }
    return register_client(test_client, payload)


@pytest.fixture(scope='session')
def confidential_client_post(test_client):
    payload = {
        'grant_types': [
            'authorization_code'
        ],
        'redirect_uris': [
            'https://localhost:5001/cb',
            'https://localhost:5003/cb'
        ],
        'token_endpoint_auth_method': 'client_secret_post',
        'name': 'confidential_client',
        'scope': "read write"
    }
    return register_client(test_client, payload)


@pytest.fixture(scope='session')
def scim_client(test_client):
    payload = {
        'grant_types': [
            'client_credentials'
        ],
        'token_endpoint_auth_method': 'client_secret_basic',
        'name': 'scim_client',
        'scope': "create_user get_user create_group get_group"
    }
    return register_client(test_client, payload)


@pytest.fixture(scope='session')
def scim_token(test_client, scim_client):
    data = {
        'grant_type': 'client_credentials',
        'client_id': scim_client['client_id'],
        'client_secret': scim_client['client_secret']
    }
    response = test_client.post('/token', data=data, content_type='application/x-www-form-urlencoded')
    assert response.status_code == 200
    return response.json['access_token']


@pytest.fixture(scope='session')
def scim_user(test_client, scim_client, scim_token):
    header = {
        'Authorization': 'Bearer ' + scim_token
    }
    data = {
        'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
        'username': 'mcescher',
        'password': 'metamorphose'
    }
    response = test_client.post(USER_PATH, data=json.dumps(data), headers=header, content_type='application/json')
    assert response.status_code == 201
    return response.json


@pytest.fixture(scope='session')
def scim_group(test_client, scim_client, scim_token):
    header = {
        'Authorization': 'Bearer ' + scim_token
    }
    data = {
        'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group'],
        'displayName': 'test_grp'
    }
    response = test_client.post(GROUP_PATH, data=json.dumps(data), headers=header, content_type='application/json')
    assert response.status_code == 201
    return response.json


@pytest.fixture(scope='session')
def usertoken(test_client, confidential_client):
    client = confidential_client
    form_vars = {
        'client_id': client['client_id'],
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
        'username': 'testuser',
        'password': 'p@ssW0rd!',
        'scope': 'openid'
    }

    response = test_client.post('/authorize', data=form_vars)
    assert response.status_code == 302
    query_params = dict(parse_qsl(urlsplit(response.headers['Location']).query))
    code = query_params['code']

    client_id = confidential_client['client_id']
    client_secret = confidential_client['client_secret']
    plaintext = f'{client_id}:{client_secret}'

    headers = {
        'Authorization': 'Basic ' + str(base64.b64encode(plaintext.encode('utf-8')), 'utf-8')
    }
    post_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': client_id,
        'scope': 'openid'
    }

    response = test_client.post('/token', headers=headers, data=post_data)
    assert response.status_code == 200
    token = response.json['access_token']
    return token


def register_client(test_client, payload):
    response = test_client.post('/register', data=json.dumps(payload), content_type='application/json')
    if response.status_code == 201:
        return response.json

    raise FixtureError('Error registering client')
