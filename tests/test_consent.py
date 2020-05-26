from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlsplit, parse_qsl


def test_post_to_consent_redirects(test_client, confidential_client):
    """
        GIVEN:  POST request to the /consent endpoint
        WHEN:   all form variables are present and correct
        THEN:   response is 302 Redirect with authorization code and state in the query parameter
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

    soup = BeautifulSoup(response.data, features="html.parser")
    client_id = soup.find('input', dict(name='client_id'))['value']
    state = soup.find('input', dict(name='state'))['value']
    id = soup.find('input', dict(name='id'))['value']

    payload = {
        'client_id': client_id,
        'state': state,
        'id': id,
        'scope0': 'read',
        'approve': 'Submit'
    }
    response = test_client.post('/consent', data=payload)
    assert response.status_code == 302
    parsed_uri = urlparse(response.headers['Location'])
    assert '{uri.scheme}://{uri.netloc}{uri.path}'.format(uri=parsed_uri) == confidential_client['redirect_uris'][0]
    query_params = dict(parse_qsl(urlsplit(response.headers['Location']).query))
    assert query_params['code']
    assert query_params['state'] == state


def test_post_to_consent_redirects_with_error(test_client, confidential_client):
    """
        GIVEN:  POST request to the /consent endpoint
        WHEN:   all form variables are present and correct, but approve is missing
        THEN:   response is 302 Redirect with error code and state in the query parameter
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

    soup = BeautifulSoup(response.data, features="html.parser")
    client_id = soup.find('input', dict(name='client_id'))['value']
    state = soup.find('input', dict(name='state'))['value']
    id = soup.find('input', dict(name='id'))['value']

    payload = {
        'client_id': client_id,
        'state': state,
        'id': id,
        'scope0': 'read'
    }
    response = test_client.post('/consent', data=payload)
    assert response.status_code == 302
    parsed_uri = urlparse(response.headers['Location'])
    assert '{uri.scheme}://{uri.netloc}{uri.path}'.format(uri=parsed_uri) == confidential_client['redirect_uris'][0]
    query_params = dict(parse_qsl(urlsplit(response.headers['Location']).query))
    assert query_params['error'] == 'access_denied'
    assert query_params['state'] == state
    assert 'code' not in query_params
