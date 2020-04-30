import json
import pytest


def test_scim_no_auth_header(test_client):
    """
        GIVEN:  POST request to the /scim/v2/User endpoint
        WHEN:   Authorization header is missing
        THEN:   server responds with 401 Unauthorized
    """
    response = test_client.post('/scim/v2/User', data=json.dumps({}), content_type='application/json')
    assert response.status_code == 401


def test_scim_invalid_auth_header(test_client, scim_client):
    """
        GIVEN:  POST request to the /scim/v2/User endpoint
        WHEN:   Authorization header is invalid
        THEN:   server responds with 401 Unauthorized
    """
    headers = {
        'Authorization': 'abc'
    }
    response = test_client.post('/scim/v2/User', data=json.dumps({}), headers=headers, content_type='application/json')
    assert response.status_code == 401


# @pytest.mark.skip(reason="WIP")
def test_scim_valid_auth_header(test_client, scim_client):
    """
        GIVEN:  POST request to the /scim/v2/User endpoint
        WHEN:   Authorization header is invalid
        THEN:   server responds with 401 Unauthorized
    """
    scim_jwt = get_scim_jwt(test_client, scim_client)
    print(scim_jwt)
    headers = {
        'Authorization': 'Bearer ' + scim_jwt
    }
    payload = {
        'username': 'jcruyff'
    }
    response = test_client.post('/scim/v2/User', data=json.dumps(payload), headers=headers, content_type='application/json')
    assert response.status_code == 201


def get_scim_jwt(test_client, scim_client):

    client_id = scim_client['client_id']
    secret = scim_client['client_secret']
    data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': secret
    }
    response = test_client.post('/token', data=data, content_type='application/x-www-form-urlencoded')
    if response.status_code == 200:
        return response.json['access_token']
    raise RuntimeError('could not get token')
