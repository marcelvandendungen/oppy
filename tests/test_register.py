import json


def test_register_endpoint_raises_error_when_redirect_uris_missing(test_client):
    """
        GIVEN:  POST request to the /register endpoint
        WHEN:   a required parameter is missing
        THEN:   response is 400 Bad Request
    """
    payload = {
        'grant_types': [
            'authorization_code'
        ]
    }
    response = test_client.post('/register', data=json.dumps(payload), content_type='application/json')
    assert response.status_code == 400
    assert response.headers['Content-Type'] == 'application/json'
    assert response.json['error'] == 'invalid_redirect_uri'
    assert response.json['error_description']


def test_register_endpoint_registers_client_successfully(test_client):
    """
        GIVEN:  POST request to the /register endpoint
        WHEN:   all required parameters are correct
        THEN:   client is registered and client id and secret are generated
    """
    payload = {
        'grant_types': [
            'authorization_code'
        ],
        'redirect_uris': [
            'http://localhost:5001/cb',
            'http://localhost:5003/cb'
        ],
        'name': 'confidential_client'
    }
    response = test_client.post('/register', data=json.dumps(payload), content_type='application/json')
    assert response.status_code == 201
    assert response.json['client_id']
    assert response.json['client_secret']
    assert response.json['name'] == 'confidential_client'
    assert 'authorization_code' in response.json['grant_types']
    assert response.json['redirect_uris'][0] == 'http://localhost:5001/cb'
    assert response.json['redirect_uris'][1] == 'http://localhost:5003/cb'
    assert response.json['token_endpoint_auth_method'] == 'client_secret_basic'


def test_register_endpoint_omits_unsupported_parameters(test_client):
    """
        GIVEN:  POST request to the /register endpoint
        WHEN:   parameters contain unsupported features
        THEN:   registration is successful, but unsupported features are not returned
    """
    payload = {
        'grant_types': [
            'authorization_code',
            'password',
            'implicit'
        ],
        'redirect_uris': [
            'http://localhost:5001/cb',
            'http://localhost:5003/cb'
        ],
        'name': 'confidential_client'
    }
    response = test_client.post('/register', data=json.dumps(payload), content_type='application/json')
    assert response.status_code == 201
    assert 'implicit' not in response.json['grant_types']
    assert 'password' not in response.json['grant_types']


def test_register_endpoint_omits_client_secret_for_public_client(test_client):
    """
        GIVEN:  POST request to the /register endpoint
        WHEN:   parameters indicate a public client is registered
        THEN:   registration is successful, but no client_secret is returned
    """
    payload = {
        'grant_types': [
            'authorization_code'
        ],
        'redirect_uris': [
            'http://localhost:5002/cb',
        ],
        'name': 'public_client',
        'token_endpoint_auth_method': 'None'    # public client
    }
    response = test_client.post('/register', data=json.dumps(payload), content_type='application/json')
    assert response.status_code == 201
    assert response.json['client_id']
    assert 'client_secret' not in response.json
    assert 'client_secret_expires_at' not in response.json
