"""
    These tests depend on 2 registered clients with ids: 'confidential_client' and 'public_client'
"""

from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlsplit, parse_qsl
from provider.model.crypto import generate_verifier, generate_challenge
from util import create_url


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
    url = create_url('/authorize', client_id='unknown_client', response_type='code')
    response = test_client.get(url)
    assert response.status_code == 400


def test_invalid_redirect_uri_results_in_error(test_client, confidential_client):
    """
        GIVEN:  GET request to the /authorize endpoint
        WHEN:   redirect_uri query parameter does not match uri registered in client
        THEN:   response is 400 Bad Request
    """
    client_id = confidential_client['client_id']
    url = create_url('/authorize', client_id=client_id, response_type='code', redirect_uri='xyz')
    response = test_client.get(url)
    assert response.status_code == 400


def test_missing_response_type_results_in_redirect(test_client, confidential_client):
    """
        GIVEN:  GET request to the /authorize endpoint
        WHEN:   response_type query parameter is missing
        THEN:   response is 302 Redirect with error query parameter
    """
    client = confidential_client
    url = create_url('/authorize', client_id=client['client_id'], redirect_uri=client['redirect_uris'][0],
                     state='96f07e0b-992a-4b5e-a61a-228bd9cfad35')
    response = test_client.get(url)
    assert response.status_code == 302
    query_params = dict(parse_qsl(urlsplit(response.headers['Location']).query))
    assert query_params['error'] == 'invalid_request'


def test_unsupported_response_type_results_in_redirect(test_client, confidential_client):
    """
        GIVEN:  GET request to the /authorize endpoint
        WHEN:   response_type query parameter is not supported
        THEN:   response is 302 Redirect with error query parameter
    """
    client = confidential_client
    url = create_url('/authorize', client_id=client['client_id'], response_type='token',
                     redirect_uri=client['redirect_uris'][0], state='96f07e0b-992a-4b5e-a61a-228bd9cfad35')
    response = test_client.get(url)
    assert response.status_code == 302
    query_params = dict(parse_qsl(urlsplit(response.headers['Location']).query))
    assert query_params['error'] == 'unsupported_response_type'


def test_query_parameters_are_reflected_in_response(test_client, confidential_client):
    """
        GIVEN:  GET request to the /authorize endpoint
        WHEN:   query parameters are specified
        THEN:   response is 200 OK with parameters as hidden input fields in the HTML
    """
    client = confidential_client
    url = create_url('/authorize', client_id=client['client_id'], redirect_uri=client['redirect_uris'][0],
                     response_type='code', state='96f07e0b-992a-4b5e-a61a-228bd9cfad35', scope='read write')
    response = test_client.get(url)
    soup = BeautifulSoup(response.data, features="html.parser")

    assert response.status_code == 200
    assert soup.find('input', dict(name='client_id'))['value'] == client['client_id']
    assert soup.find('input', dict(name='redirect_uri'))['value'] == client['redirect_uris'][0]
    assert soup.find('input', dict(name='state'))['value'] == '96f07e0b-992a-4b5e-a61a-228bd9cfad35'
    assert soup.find('input', dict(name='scope'))['value'] == 'read write'


def test_invalid_scope_returns_error(test_client, confidential_client):
    """
        GIVEN:  GET request to the /authorize endpoint
        WHEN:   query parameters are specified, scope is invalid
        THEN:   response is 302 Redirect with error parameters
    """
    client = confidential_client
    url = create_url('/authorize', client_id=client['client_id'], redirect_uri=client['redirect_uris'][0],
                     response_type='code', state='96f07e0b-992a-4b5e-a61a-228bd9cfad35', scope='scope1 scope2')
    response = test_client.get(url)
    assert response.status_code == 302
    query_params = dict(parse_qsl(urlsplit(response.headers['Location']).query))
    assert query_params['error'] == 'invalid_scope'
    assert query_params['error_description'] == 'One or more scopes are invalid'


def test_missing_query_parameters_not_reflected_in_response(test_client, confidential_client):
    """
        GIVEN:  GET request to the /authorize endpoint
        WHEN:   query parameters are specified, but no 'state' or 'nonce' query parameters
        THEN:   response is 200 OK and no hidden input fields with name 'state' or 'nonce' in the HTML
    """
    client = confidential_client
    url = create_url('/authorize', client_id=client['client_id'], redirect_uri=client['redirect_uris'][0],
                     response_type='code')
    response = test_client.get(url)
    soup = BeautifulSoup(response.data, features="html.parser")

    assert response.status_code == 200
    assert soup.find('input', dict(name='state')) is None
    assert soup.find('scope', dict(name='scope')) is None
    assert soup.find('input', dict(name='nonce')) is None


def test_confidential_client_without_code_challenge_results_in_error(test_client, public_client):
    """
        GIVEN:  GET request to the /authorize endpoint
        WHEN:   client_id identifies a public client and code_challenge query parameter is missing
        THEN:   response is 302 Redirect with error query parameter (PKCE required for public clients)
    """
    client = public_client
    url = create_url('/authorize', client_id=client['client_id'], redirect_uri=client['redirect_uris'][0],
                     response_type='code', state='96f07e0b-992a-4b5e-a61a-228bd9cfad35')
    response = test_client.get(url)
    assert response.status_code == 302
    query_params = dict(parse_qsl(urlsplit(response.headers['Location']).query))
    assert query_params['error'] == 'invalid_request'
    assert query_params['error_description'] == 'code challenge required'


def test_post_to_authorize_issues_code(test_client, confidential_client):
    """
        GIVEN:  POST request to the /authorize endpoint
        WHEN:   all required form variables are present and correct
        THEN:   response is 302 Redirect to registered redirect_uri with code and state query parameters
    """

    client = confidential_client
    form_vars = {
        'client_id': client['client_id'],
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
        'username': 'testuser',
        'password': 'p@ssW0rd!'
    }

    response = test_client.post('/authorize', data=form_vars)
    assert response.status_code == 302
    parsed_uri = urlparse(response.headers['Location'])
    assert '{uri.scheme}://{uri.netloc}{uri.path}'.format(uri=parsed_uri) == client['redirect_uris'][0]
    query_params = dict(parse_qsl(urlsplit(response.headers['Location']).query))
    assert query_params['code']
    assert query_params['state'] == '96f07e0b-992a-4b5e-a61a-228bd9cfad35'


def test_post_to_authorize_with_invalid_credentials_displays_error(test_client, confidential_client):
    """
        GIVEN:  POST request to the /authorize endpoint
        WHEN:   all required form variables are present, but credentials are incorrect
        THEN:   response is 200 Ok with login page including div with error notification
    """

    client = confidential_client
    form_vars = {
        'client_id': client['client_id'],
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
        'username': 'testuser',
        'password': 'password'
    }

    response = test_client.post('/authorize', data=form_vars)
    assert response.status_code == 200
    soup = BeautifulSoup(response.data, features="html.parser")
    assert 'Those credentials did not work' in soup.find('div', class_='warning').string


def test_post_to_authorize_with_whitelisted_redirect_uri_redirects_correctly(test_client, confidential_client):
    """
        GIVEN:  POST request to the /authorize endpoint
        WHEN:   all form variables are present, correct and include whitelisted redirect uri
        THEN:   response is 302 Redirect to specified redirect_uri with code and state query parameters
    """

    client = confidential_client
    form_vars = {
        'client_id': client['client_id'],
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
        'username': 'testuser',
        'password': 'p@ssW0rd!',
        'redirect_uri': client['redirect_uris'][1]
    }

    response = test_client.post('/authorize', data=form_vars)
    assert response.status_code == 302
    parsed_uri = urlparse(response.headers['Location'])
    assert '{uri.scheme}://{uri.netloc}{uri.path}'.format(uri=parsed_uri) == client['redirect_uris'][1]
    query_params = dict(parse_qsl(urlsplit(response.headers['Location']).query))
    assert query_params['code']
    assert query_params['state'] == '96f07e0b-992a-4b5e-a61a-228bd9cfad35'


def test_post_to_authorize_with_non_whitelisted_redirect_uri_raises_error(test_client, confidential_client):
    """
        GIVEN:  POST request to the /authorize endpoint
        WHEN:   all form variables are present, correct and include whitelisted redirect uri
        THEN:   response is 302 Redirect to specified redirect_uri with code and state query parameters
    """

    client = confidential_client
    form_vars = {
        'client_id': client['client_id'],
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
        'username': 'testuser',
        'password': 'p@ssW0rd!',
        'redirect_uri': 'https://localhost:5004/cb'
    }

    response = test_client.post('/authorize', data=form_vars)
    assert response.status_code == 400
    assert response.data == b'Error occurred: Not a registered redirect uri'


def test_post_to_authorize_raised_error_if_client_id_is_missing(test_client):
    """
        GIVEN:  POST request to the /authorize endpoint
        WHEN:   client id is missing from form variables
        THEN:   response is 400 Bad Request
    """

    form_vars = {
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
        'username': 'testuser',
        'password': 'p@ssW0rd!'
    }

    response = test_client.post('/authorize', data=form_vars)
    assert response.status_code == 400


def test_post_to_authorize_raised_error_if_username_is_missing(test_client, public_client):
    """
        GIVEN:  POST request to the /authorize endpoint
        WHEN:   client id is missing from form variables
        THEN:   response is 400 Bad Request
    """

    client = public_client
    form_vars = {
        'client_id': client['client_id'],
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
        'password': 'p@ssW0rd!'
    }

    response = test_client.post('/authorize', data=form_vars)
    assert response.status_code == 400


def test_post_to_authorize_raised_error_if_password_is_missing(test_client, public_client):
    """
        GIVEN:  POST request to the /authorize endpoint
        WHEN:   client id is missing from form variables
        THEN:   response is 400 Bad Request
    """

    client = public_client
    form_vars = {
        'client_id': client['client_id'],
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
        'username': 'testuser',
    }

    response = test_client.post('/authorize', data=form_vars)
    assert response.status_code == 400


def test_post_to_authorize_raises_error_when_code_challenge_is_missing_for_public_client(test_client,
                                                                                         public_client):

    client = public_client
    form_vars = {
        'client_id': client['client_id'],
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
        'username': 'testuser',
        'password': 'p@ssW0rd!'
    }

    response = test_client.post('/authorize', data=form_vars)
    assert response.status_code == 302
    query_params = dict(parse_qsl(urlsplit(response.headers['Location']).query))
    assert 'code' not in query_params
    assert query_params['error'] == 'invalid_request'


def test_post_to_authorize_issues_code_for_public_client(test_client, public_client):
    """
        GIVEN:  POST request to the /authorize endpoint
        WHEN:   all form variables are present and correct
        THEN:   response is 302 Redirect with code and state query parameters
    """

    client = public_client
    code_verifier = generate_verifier()
    code_challenge = generate_challenge(code_verifier)

    form_vars = {
        'client_id': client['client_id'],
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
        'username': 'testuser',
        'password': 'p@ssW0rd!',
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }
    # make authentication request -> verifies code verifier matches challenge
    response = test_client.post('/authorize', data=form_vars)
    assert response.status_code == 302
    query_params = dict(parse_qsl(urlsplit(response.headers['Location']).query))
    assert query_params['code']
    assert query_params['state'] == '96f07e0b-992a-4b5e-a61a-228bd9cfad35'


def test_post_to_authorize_with_non_consented_user_returns_consent_page(test_client, confidential_client):
    """
        GIVEN:  POST request to the /authorize endpoint
        WHEN:   all form variables are present, correct, but user has not given consent yet
        THEN:   response is 200 Ok with consent page with checkboxes for each scope
    """

    client = confidential_client
    form_vars = {
        'client_id': client['client_id'],
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
        'username': 'mvandend',
        'password': 'p@ssW0rd!',
        'scope': 'read write'
    }

    response = test_client.post('/authorize', data=form_vars)
    assert response.status_code == 200
    assert response.headers['Content-Type'].startswith('text/html')

    soup = BeautifulSoup(response.data, features="html.parser")
    assert soup.find('input', dict(name='client_id'))['value'] == client['client_id']
    assert soup.find('input', dict(name='state'))['value'] == form_vars['state']
    assert soup.find('input', dict(name='id'))['value']

    checkbox = soup.find('input', dict(name='scopes0'))
    assert 'read' in checkbox.nextSibling
    checkbox = soup.find('input', dict(name='scopes1'))
    assert 'write' in checkbox.nextSibling


def test_post_to_authorize_issues_code_using_form_post(test_client, confidential_client):
    """
        GIVEN:  POST request to the /authorize endpoint
        WHEN:   all required form variables are present and correct, includes response_mode=form_post
        THEN:   response is 200 OK with auto-submit form posting to redirect_uri with code and state form fields
    """

    client = confidential_client
    form_vars = {
        'client_id': client['client_id'],
        'state': '96f07e0b-992a-4b5e-a61a-228bd9cfad35',
        'username': 'testuser',
        'password': 'p@ssW0rd!',
        'response_mode': 'form_post'
    }

    response = test_client.post('/authorize', data=form_vars)
    assert response.status_code == 200
    assert response.headers['Content-Type'].startswith('text/html')

    soup = BeautifulSoup(response.data, features="html.parser")
    assert soup.find('input', dict(name='code'))['value']
    assert soup.find('input', dict(name='state'))['value'] == form_vars['state']
