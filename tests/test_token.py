import pytest
from urllib.parse import urlsplit, parse_qsl


@pytest.mark.parametrize(('parameter'), ('grant_type', 'client_id', 'code'))
def test_token_endpoint_raises_error_when_required_parameters_missing(test_client, parameter):
    """
        GIVEN:  POST request to the /token endpoint
        WHEN:   a required parameter is missing
        THEN:   response is 400 Bad Request
    """

    code, _ = authenticate_user(test_client)

    form_vars = {
        'grant_type': 'authorization_code',
        'client_id': 'confidential_client',
        'code': code,
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35'
    }
    del form_vars[parameter]

    response = test_client.post('/token', data=form_vars)
    assert response.status_code == 400
    assert response.data == b'Error occurred: invalid_request - %b parameter is missing' % parameter.encode()


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


def test_token_endpoint_raises_error_when_authorization_request_not_found(test_client):
    """
        GIVEN:  POST request to the /token endpoint
        WHEN:   all form variables are present and correct, but client id does not identify registered client
        THEN:   response is 400 Bad Request
    """

    post_data = {
        'grant_type': 'authorization_code',
        'code': 'unknown',
        'client_id': 'confidential_client'
    }
    response = test_client.post('/token', data=post_data)
    assert response.status_code == 400


def test_token_endpoint_raises_error_for_unknown_client(test_client):
    """
        GIVEN:  POST request to the /token endpoint
        WHEN:   all form variables are present and correct, but client id does not identify registered client
        THEN:   response is 400 Bad Request
    """

    form_vars = {
        'client_id': 'confidential_client',
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
        'username': 'test_user',
        'password': 'P@ssW0rd123'
    }
    response = test_client.post('/authorize', data=form_vars)
    assert response.status_code == 302

    post_data = {
        'grant_type': 'authorization_code',
        'client_id': 'unknown_client'
    }
    response = test_client.post('/token', data=post_data)
    assert response.status_code == 400


def test_token_endpoint_issues_token(test_client):
    """
        GIVEN:  POST request to the /token endpoint
        WHEN:   all form variables are present and correct
        THEN:   response is 200 OK with access token in the JSON payload
    """

    code, _ = authenticate_user(test_client)

    post_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': 'confidential_client'
    }
    response = test_client.post('/token', data=post_data)
    assert response.status_code == 200


def authenticate_user(test_client):
    """
      POST to the authorize endpoint to authenticate the user and generate an authorization code
    """

    form_vars = {
        'client_id': 'confidential_client',
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
        'username': 'test_user',
        'password': 'P@ssW0rd123'
    }
    response = test_client.post('/authorize', data=form_vars)
    assert response.status_code == 302

    query_params = dict(parse_qsl(urlsplit(response.headers['Location']).query))
    code = query_params['code']
    state = query_params['state'] == '96f07e0b-992a-4b5e-a61a-228bd9cfad35'

    return (code, state)
