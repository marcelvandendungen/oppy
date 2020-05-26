import base64
from bs4 import BeautifulSoup
from urllib.parse import urlencode
from test_token import authenticate_user, decode_token


def test_logout_endpoint_with_id_token(test_client, confidential_client):
    """
        GIVEN:  GET request to the /logout endpoint
        WHEN:   id_token passed in as id_token_hint
        THEN:   response is 200 OK with HTML page containing IFRAME to logout client
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
        'scope': 'openid',
        'client_id': client_id
    }

    response = test_client.post('/token', headers=headers, data=post_data)
    assert response.status_code == 200

    post_logout_uri = "https://localhost:5001/logged_out"
    query_params = {
        'id_token_hint': response.json['id_token'],
        'post_logout_redirect_uri': post_logout_uri
    }
    response = test_client.get('/logout?' + urlencode(query_params))
    assert response.status_code == 200
    assert response.headers['Content-Type'].startswith('text/html')

    soup = BeautifulSoup(response.data, features="html.parser")
    # check for IFRAME with src attribute
    iframes = soup.findAll('iframe')
    assert len(iframes) == 1
    assert iframes[0]['src'] == 'https://localhost:5001/logout'
    # check for SCRIPT element
    script = soup.findAll('script')[1].text
    assert 'redirect_url = "https://localhost:5001/logged_out"' in script