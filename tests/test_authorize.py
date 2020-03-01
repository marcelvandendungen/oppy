"""
    These tests depend on 2 registered clients with ids: 'confidential_client' and 'public_client'
"""

from bs4 import BeautifulSoup
from urllib.parse import urlencode, urlsplit, parse_qsl


def test_missing_client_id_results_in_error(test_client):
    """
        GIVEN:  GET request to the /authorize endpoint
        WHEN:   client_id query parameter is missing
        THEN:   response is 400 Bad Request
    """
    url = create_url('/authorize')
    response = test_client.get(url)
    assert response.status_code == 400


def test_invalid_client_id_results_in_error(test_client):
    """
        GIVEN:  GET request to the /authorize endpoint
        WHEN:   client_id query parameter is not registered
        THEN:   response is 400 Bad Request
    """
    url = create_url('/authorize', client_id='unknown_client', response_type='code', redirect_uri='xyz')
    response = test_client.get(url)
    assert response.status_code == 400


def test_invalid_redirect_uri_results_in_error(test_client):
    """
        GIVEN:  GET request to the /authorize endpoint
        WHEN:   redirect_uri query parameter does not match uri registered in client
        THEN:   response is 400 Bad Request
    """
    url = create_url('/authorize', client_id='confidential_client', response_type='code', redirect_uri='xyz')
    response = test_client.get(url)
    assert response.status_code == 400


def test_missing_response_type_results_in_redirect(test_client):
    """
        GIVEN:  GET request to the /authorize endpoint
        WHEN:   response_type query parameter is missing
        THEN:   response is 302 Redirect with error query parameter
    """
    url = create_url('/authorize', client_id='confidential_client', redirect_uri='http://localhost:5001/cb',
                     state='96f07e0b-992a-4b5e-a61a-228bd9cfad35')
    response = test_client.get(url)
    assert response.status_code == 302
    query_params = dict(parse_qsl(urlsplit(response.headers['Location']).query))
    assert query_params['error'] == 'invalid_request'


def test_unsupported_response_type_results_in_redirect(test_client):
    """
        GIVEN:  GET request to the /authorize endpoint
        WHEN:   response_type query parameter is not supported
        THEN:   response is 302 Redirect with error query parameter
    """
    url = create_url('/authorize', client_id='confidential_client', response_type='token',
                     redirect_uri='http://localhost:5001/cb', state='96f07e0b-992a-4b5e-a61a-228bd9cfad35')
    response = test_client.get(url)
    assert response.status_code == 302
    query_params = dict(parse_qsl(urlsplit(response.headers['Location']).query))
    assert query_params['error'] == 'unsupported_response_type'


def test_query_parameters_are_reflected_in_response(test_client):
    """
        GIVEN:  GET request to the /authorize endpoint
        WHEN:   query parameters are specified
        THEN:   response is 200 OK with parameters as hidden input fields in the HTML
    """
    url = create_url('/authorize', client_id='confidential_client', redirect_uri='http://localhost:5001/cb',
                     response_type='code', state='96f07e0b-992a-4b5e-a61a-228bd9cfad35', scope='scope1 scope2')
    response = test_client.get(url)
    soup = BeautifulSoup(response.data, features="html.parser")

    assert response.status_code == 200
    assert soup.find('input', dict(name='client_id'))['value'] == 'confidential_client'
    assert soup.find('input', dict(name='redirect_uri'))['value'] == 'http://localhost:5001/cb'
    assert soup.find('input', dict(name='state'))['value'] == '96f07e0b-992a-4b5e-a61a-228bd9cfad35'
    assert soup.find('input', dict(name='scope'))['value'] == 'scope1 scope2'


def test_missing_query_parameters_not_reflected_in_response(test_client):
    """
        GIVEN:  GET request to the /authorize endpoint
        WHEN:   query parameters are specified, but no 'state' or 'nonce' query parameters
        THEN:   response is 200 OK and no hidden input fields with name 'state' or 'nonce' in the HTML
    """
    url = create_url('/authorize', client_id='confidential_client', redirect_uri='http://localhost:5001/cb',
                     response_type='code')
    response = test_client.get(url)
    soup = BeautifulSoup(response.data, features="html.parser")

    assert response.status_code == 200
    assert soup.find('input', dict(name='state')) is None
    assert soup.find('scope', dict(name='scope')) is None
    assert soup.find('input', dict(name='nonce')) is None


def test_confidential_client_without_code_challenge_results_in_error(test_client):
    """
        GIVEN:  GET request to the /authorize endpoint
        WHEN:   client_id identifies a public client and code_challenge query parameter is missing
        THEN:   response is 302 Redirect with error query parameter (PKCE required for public clients)
    """
    url = create_url('/authorize', client_id='public_client', redirect_uri='http://localhost:5002/cb',
                     response_type='code', state='96f07e0b-992a-4b5e-a61a-228bd9cfad35')
    response = test_client.get(url)
    assert response.status_code == 302
    query_params = dict(parse_qsl(urlsplit(response.headers['Location']).query))
    assert query_params['error'] == 'invalid_request'
    assert query_params['error_description'] == 'code challenge required'


def test_post_to_authorize_issues_code(test_client):
    """
        GIVEN:  POST request to the /authorize endpoint
        WHEN:   all form variables are present and correct
        THEN:   response is 302 Redirect with code and state query parameters
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
    assert query_params['code']
    assert query_params['state'] == '96f07e0b-992a-4b5e-a61a-228bd9cfad35'


def test_post_to_authorize_raised_error_if_client_id_is_missing(test_client):
    """
        GIVEN:  POST request to the /authorize endpoint
        WHEN:   client id is missing from form variables
        THEN:   response is 400 Bad Request
    """

    form_vars = {
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
        'username': 'test_user',
        'password': 'P@ssW0rd123'
    }

    response = test_client.post('/authorize', data=form_vars)
    assert response.status_code == 400


def test_post_to_authorize_raised_error_if_username_is_missing(test_client):
    """
        GIVEN:  POST request to the /authorize endpoint
        WHEN:   client id is missing from form variables
        THEN:   response is 400 Bad Request
    """

    form_vars = {
        'client_id': 'public_client',
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
        'password': 'P@ssW0rd123'
    }

    response = test_client.post('/authorize', data=form_vars)
    assert response.status_code == 400


def test_post_to_authorize_raised_error_if_password_is_missing(test_client):
    """
        GIVEN:  POST request to the /authorize endpoint
        WHEN:   client id is missing from form variables
        THEN:   response is 400 Bad Request
    """

    form_vars = {
        'client_id': 'public_client',
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
        'username': 'test_user',
    }

    response = test_client.post('/authorize', data=form_vars)
    assert response.status_code == 400


def test_post_to_authorize_raises_error_when_code_challenge_is_missing_for_public_client(test_client):

    form_vars = {
        'client_id': 'public_client',
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
        'username': 'test_user',
        'password': 'P@ssW0rd123'
    }

    response = test_client.post('/authorize', data=form_vars)
    assert response.status_code == 302
    query_params = dict(parse_qsl(urlsplit(response.headers['Location']).query))
    assert 'code' not in query_params
    assert query_params['error'] == 'invalid_request'


def test_post_to_authorize_issues_code_for_public_client(test_client):
    """
        GIVEN:  POST request to the /authorize endpoint
        WHEN:   all form variables are present and correct
        THEN:   response is 302 Redirect with code and state query parameters
    """

    form_vars = {
        'client_id': 'public_client',
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
        'username': 'test_user',
        'password': 'P@ssW0rd123',
        'code_challenge': 'abcdef',
        'code_challenge_method': 'SHA256'
    }

    # make authentication request -> verifies code verifier matches challenge
    response = test_client.post('/authorize', data=form_vars)
    assert response.status_code == 302
    query_params = dict(parse_qsl(urlsplit(response.headers['Location']).query))
    assert query_params['code']
    assert query_params['state'] == '96f07e0b-992a-4b5e-a61a-228bd9cfad35'


def create_url(path, **query_params):
    return path + '?' + urlencode(query_params)
