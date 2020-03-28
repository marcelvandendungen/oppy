from provider.app import app

import json
import pytest


@pytest.fixture(scope='session')
def test_client():
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
        'name': 'confidential_client'
    }
    response = test_client.post('/register', data=json.dumps(payload), content_type='application/json')
    if response.status_code == 201:
        return response.json

    raise RuntimeError('Error registering client')


@pytest.fixture(scope='session')
def public_client(test_client):
    payload = {
        'client_id': 'public_client',
        'redirect_uris': ['https://localhost:5002/cb'],
        'token_endpoint_auth_method': 'None',
        'name': 'public_client'
    }
    response = test_client.post('/register', data=json.dumps(payload), content_type='application/json')
    if response.status_code == 201:
        return response.json

    raise RuntimeError('Error registering client')
