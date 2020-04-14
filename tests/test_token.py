import base64
import freezegun
import jwt
import pytest
from urllib.parse import urlsplit, parse_qsl


@pytest.mark.parametrize(('parameter'), ('grant_type', 'client_id', 'code'))
def test_token_endpoint_raises_error_when_required_parameters_missing(test_client, parameter,
                                                                      confidential_client):
    """
        GIVEN:  POST request to the /token endpoint
        WHEN:   a required parameter is missing
        THEN:   response is 400 Bad Request
    """

    code, _ = authenticate_user(test_client, confidential_client)

    client_id = confidential_client['client_id']
    form_vars = {
        'grant_type': 'authorization_code',
        'client_id': client_id,
        'code': code,
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35'
    }
    del form_vars[parameter]

    response = test_client.post('/token', data=form_vars)
    assert response.status_code == 400
    assert response.json['error'] == 'invalid_request'
    assert response.json['error_description'] == '%s parameter is missing' % parameter


def test_token_endpoint_raises_error_for_unsupported_grant_type(test_client):
    """
        GIVEN:  POST request to the /token endpoint
        WHEN:   the grant_type is not supported
        THEN:   response is 400 Bad Request
    """

    post_data = {
        'grant_type': 'implicit'

    }
    response = test_client.post('/token', data=post_data)
    assert response.status_code == 400


def test_token_endpoint_raises_error_when_authorization_request_not_found(test_client, confidential_client):
    """
        GIVEN:  POST request to the /token endpoint
        WHEN:   all form variables are present and correct, but client id does not identify registered client
        THEN:   response is 400 Bad Request
    """

    client_id = confidential_client['client_id']
    post_data = {
        'grant_type': 'authorization_code',
        'code': 'unknown',
        'client_id': client_id
    }
    response = test_client.post('/token', data=post_data)
    assert response.status_code == 400


def test_token_endpoint_raises_error_for_unknown_client(test_client, confidential_client):
    """
        GIVEN:  POST request to the /token endpoint
        WHEN:   all form variables are present and correct, but client id does not identify registered client
        THEN:   response is 400 Bad Request
    """

    client_id = confidential_client['client_id']
    form_vars = {
        'client_id': client_id,
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
        'username': 'testuser',
        'password': 'p@ssW0rd!'
    }
    response = test_client.post('/authorize', data=form_vars)
    assert response.status_code == 302

    post_data = {
        'grant_type': 'authorization_code',
        'client_id': 'unknown_client'
    }
    response = test_client.post('/token', data=post_data)
    assert response.status_code == 400


def test_token_endpoint_issues_token(test_client, confidential_client):
    """
        GIVEN:  POST request to the /token endpoint
        WHEN:   all form variables are present and correct
        THEN:   response is 200 OK with access token in the JSON payload
    """

    code, _ = authenticate_user(test_client, confidential_client)

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
        'scope': 'write read'
    }

    with freezegun.freeze_time("2020-03-14 12:00:00"):
        response = test_client.post('/token', headers=headers, data=post_data)

        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'application/json'
        assert response.json['expires_in'] == 3600
        assert response.json['token_type'] == 'Bearer'
        token = decode_token(response.json['access_token'])
        assert token['aud'] == 'urn:my_service'
        assert token['iat'] == 1584187200
        assert token['nbf'] == 1584187200
        assert token['exp'] == 1584190800
        assert response.json['refresh_token']

    # try to reuse same auto code to ensure code can only be used once
    with freezegun.freeze_time("2020-03-14 12:01:00"):
        response = test_client.post('/token', headers=headers, data=post_data)

        assert response.status_code == 400
        assert response.json['error'] == 'invalid_request'
        assert response.json['error_description'] == 'authorization request not found'


def test_token_endpoint_fails_on_expired_code(test_client, confidential_client):
    """
        GIVEN:  POST request to the /token endpoint
        WHEN:   all form variables are present but authorization code is old
        THEN:   response is 400 Bad Request
    """

    with freezegun.freeze_time("2020-03-14 12:00:00"):
        code, _ = authenticate_user(test_client, confidential_client)

    client_id = confidential_client['client_id']
    post_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': client_id
    }

    with freezegun.freeze_time("2020-03-14 12:06:00"):
        response = test_client.post('/token', data=post_data)

        assert response.status_code == 400
        assert response.json['error'] == 'invalid_request'
        assert response.json['error_description'] == 'auth code is expired'


def test_token_refresh(test_client, confidential_client):
    """
        GIVEN:  POST refresh_token request to the /token endpoint
        WHEN:   all required form variables are present and correct
        THEN:   response is 200 OK with new access token in the JSON payload
    """
    code, _ = authenticate_user(test_client, confidential_client)

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
        'scope': 'read write'
    }

    # get the initial refresh_token
    with freezegun.freeze_time("2020-03-14 12:00:00"):
        response = test_client.post('/token', headers=headers, data=post_data)

        assert response.status_code == 200
        refresh_token = response.json['refresh_token']

    post_data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token
    }
    # use refresh token to get new access_token
    with freezegun.freeze_time("2020-03-14 13:01:00"):
        response = test_client.post('/token', headers=headers, data=post_data)

        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'application/json'
        assert response.json['expires_in'] == 3600
        assert response.json['token_type'] == 'Bearer'
        token = decode_token(response.json['access_token'])
        assert token['aud'] == 'urn:my_service'
        assert token['sub']
        assert token['iat'] == 1584190860
        assert token['nbf'] == 1584190860
        assert token['exp'] == 1584194460
        assert response.json['refresh_token']


def test_token_refresh_invalid(test_client):
    """
        GIVEN:  POST refresh_token request to the /token endpoint
        WHEN:   the refresh token is present but not correct
        THEN:   response is 400 Bad Request
    """

    post_data = {
        'grant_type': 'refresh_token',
        'refresh_token': "invalid_refresh_token"
    }
    # use invalid refresh token to get new access_token
    with freezegun.freeze_time("2020-03-14 13:01:00"):
        response = test_client.post('/token', data=post_data)
        assert response.status_code == 400
        assert response.headers['Content-Type'] == 'application/json'
        assert response.json['error'] == 'invalid_grant'
        assert response.json['error_description'] == 'unknown refresh token'


def test_token_endpoint_issues_token_using_client_credentials(test_client, confidential_client):
    """
        GIVEN:  POST request to the /token endpoint
        WHEN:   all form variables are present and correct
        THEN:   response is 200 OK with access token in the JSON payload
    """

    client_id = confidential_client['client_id']
    client_secret = confidential_client['client_secret']
    plaintext = f'{client_id}:{client_secret}'

    headers = {
        'Authorization': 'Basic ' + str(base64.b64encode(plaintext.encode('utf-8')), 'utf-8')
    }
    post_data = {
        'grant_type': 'client_credentials',
        'scope': 'read write'
    }

    with freezegun.freeze_time("2020-03-14 12:00:00"):
        response = test_client.post('/token', headers=headers, data=post_data)

        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'application/json'
        assert response.json['expires_in'] == 3600
        assert response.json['token_type'] == 'Bearer'
        token = decode_token(response.json['access_token'])
        assert token['aud'] == 'urn:my_service'
        assert token['sub'] == client_id
        assert token['iat'] == 1584187200
        assert token['nbf'] == 1584187200
        assert token['exp'] == 1584190800
        assert response.json['refresh_token']


def test_token_endpoint_using_client_credentials_post(test_client, confidential_client_post):
    """
        GIVEN:  POST request to the /token endpoint
        WHEN:   all form variables are present and correct
        THEN:   response is 200 OK with access token in the JSON payload
    """

    client_id = confidential_client_post['client_id']
    post_data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': confidential_client_post['client_secret']
    }

    with freezegun.freeze_time("2020-03-14 12:00:00"):
        response = test_client.post('/token', data=post_data)

        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'application/json'
        assert response.json['expires_in'] == 3600
        assert response.json['token_type'] == 'Bearer'
        token = decode_token(response.json['access_token'])
        assert token['aud'] == 'urn:my_service'
        assert token['sub'] == client_id
        assert token['iat'] == 1584187200
        assert token['nbf'] == 1584187200
        assert token['exp'] == 1584190800
        assert response.json['refresh_token']


def test_token_endpoint_issues_token_with_requested_scopes(test_client, confidential_client):
    """
        GIVEN:  POST request to the /token endpoint
        WHEN:   all form variables are present and correct, but requested scope is subset of allowed scopes
        THEN:   response is 200 OK with access token for only requested scope
    """
    assert NotImplementedError()


def test_token_endpoint_issues_id_token(test_client, confidential_client):
    """
        GIVEN:  POST request to the /token endpoint
        WHEN:   all form variables are present and correct and openid is specified in scope
        THEN:   response is 200 OK with access token and id token in the JSON payload
    """

    code, _ = authenticate_user(test_client, confidential_client, scope='write read openid')

    client_id = confidential_client['client_id']
    client_secret = confidential_client['client_secret']
    plaintext = f'{client_id}:{client_secret}'

    headers = {
        'Authorization': 'Basic ' + str(base64.b64encode(plaintext.encode('utf-8')), 'utf-8')
    }
    post_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'scope': 'read write, openid',
        'client_id': client_id
    }

    with freezegun.freeze_time("2020-03-14 12:00:00"):
        response = test_client.post('/token', headers=headers, data=post_data)

        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'application/json'
        assert response.json['expires_in'] == 3600
        assert response.json['token_type'] == 'Bearer'
        token = decode_token(response.json['access_token'])
        assert token['aud'] == 'urn:my_service'
        assert token['sub']
        assert token['iat'] == 1584187200
        assert token['nbf'] == 1584187200
        assert token['exp'] == 1584190800
        assert response.json['refresh_token']
        token = decode_token(response.json['id_token'], audience=client_id)
        assert token['aud'] == client_id
        assert token['name'] == 'Test User'
        assert token['sub']
        assert token['iat'] == 1584187200
        assert token['nbf'] == 1584187200
        assert token['exp'] == 1584190800


@pytest.mark.skip("WIP")
def test_token_endpoint_single_sign_on(test_client, confidential_client):
    """
        GIVEN:  Successful retrieval of tokens after sign in
        WHEN:   another authorization request with different scope is executed
        THEN:   auth code is issued without login screen being presented
    """

    code, _ = authenticate_user(test_client, confidential_client, scope='openid')

    client_id = confidential_client['client_id']
    client_secret = confidential_client['client_secret']
    plaintext = f'{client_id}:{client_secret}'

    headers = {
        'Authorization': 'Basic ' + str(base64.b64encode(plaintext.encode('utf-8')), 'utf-8')
    }
    post_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'scope': 'openid',
        'client_id': client_id
    }

    with freezegun.freeze_time("2020-03-14 12:00:00"):
        response = test_client.post('/token', headers=headers, data=post_data)

        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'application/json'
        assert response.json['expires_in'] == 3600
        assert response.json['token_type'] == 'Bearer'
        token = decode_token(response.json['access_token'], audience='https://localhost:5000/')
        assert token['aud'] == 'https://localhost:5000/'
        assert token['sub']
        assert token['iat'] == 1584187200
        assert token['nbf'] == 1584187200
        assert token['exp'] == 1584190800
        assert response.json['refresh_token']
        token = decode_token(response.json['id_token'], audience=client_id)
        assert token['aud'] == client_id
        assert token['name'] == 'Test User'
        assert token['sub']
        assert token['iat'] == 1584187200
        assert token['nbf'] == 1584187200
        assert token['exp'] == 1584190800

        form_vars = {
            'client_id': client_id,
            'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
            'scope': 'read write'
        }

        response = test_client.post('/authorize', data=form_vars)

        assert response.status_code == 200
        assert response.headers['Content-Type'].startswith('text/html')


def decode_token(encoded, audience='urn:my_service'):
    with open("./public.pem", "rb") as f:
        public_key = f.read()

    token = jwt.decode(encoded, public_key, audience=audience, algorithms='RS256')
    return token


def authenticate_user(test_client, client, scope='write read'):
    """
      POST to the authorize endpoint to authenticate the user and generate an authorization code
    """

    client_id = client['client_id']
    form_vars = {
        'client_id': client_id,
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
        'username': 'testuser',
        'password': 'p@ssW0rd!',
        'scope': scope
    }
    response = test_client.post('/authorize', data=form_vars)
    assert response.status_code == 302

    query_params = dict(parse_qsl(urlsplit(response.headers['Location']).query))
    code = query_params['code']
    state = query_params['state'] == '96f07e0b-992a-4b5e-a61a-228bd9cfad35'

    return (code, state)
