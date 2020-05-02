import json

from provider.endpoints.scim.scim import USER_PATH, GROUP_PATH


def test_scim_no_auth_header(test_client):
    """
        GIVEN:  POST request to the /scim/v2/Users endpoint
        WHEN:   Authorization header is missing
        THEN:   server responds with 401 Unauthorized
    """
    response = test_client.post(USER_PATH, data=json.dumps({}), content_type='application/json')
    assert response.status_code == 401


def test_scim_invalid_auth_header(test_client, scim_client):
    """
        GIVEN:  POST request to the /scim/v2/Users endpoint
        WHEN:   Authorization header is invalid
        THEN:   server responds with 401 Unauthorized
    """
    headers = {
        'Authorization': 'abc'
    }
    response = test_client.post(USER_PATH, data=json.dumps({}), headers=headers, content_type='application/json')
    assert response.status_code == 401


def test_scim_create_user_failed(test_client, scim_client, scim_token):
    """
        GIVEN:  POST request to the /scim/v2/Users endpoint
        WHEN:   Authorization header is valid, but schemas field is missing from post data
        THEN:   server responds with 400 Bad Request and SCIM error representation
    """

    header = {
        'Authorization': 'Bearer ' + scim_token
    }
    data = {
        'username': 'jcruyff'
    }
    response = test_client.post(USER_PATH, data=json.dumps(data), headers=header, content_type='application/json')
    assert response.status_code == 400
    assert response.json['schemas'] == ['urn:ietf:params:scim:api:messages:2.0:Error']
    assert response.json['status'] == str(response.status_code)
    assert response.json['detail'] == 'Unsupported schema'
    assert response.json['scimType'] == 'invalidValue'


# @pytest.mark.skip(reason="WIP")
def test_scim_create_user(test_client, scim_client, scim_token):
    """
        GIVEN:  POST request to the /scim/v2/Users endpoint
        WHEN:   Authorization header is valid
        THEN:   server responds with 201 Created and the representation of the user created
    """

    header = {
        'Authorization': 'Bearer ' + scim_token
    }
    data = {
        'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
        'username': 'jcruyff'
    }
    response = test_client.post(USER_PATH, data=json.dumps(data), headers=header, content_type='application/json')
    assert response.status_code == 201
    assert response.headers['ETag'] == response.json['meta']['version']
    assert response.json['username'] == 'jcruyff'
    assert response.json['active'] is True
    assert response.json['meta']['resourceType'] == 'User'
    assert response.json['meta']['location'] == 'https://localhost:5000/scim/v2/Users/' + response.json['id']


def test_scim_get_user(test_client, scim_user, scim_token):
    """
        GIVEN:  GET request to the /scim/v2/Users/<id> endpoint
        WHEN:   Authorization header is valid
        THEN:   server responds with 200 OK and the representation of the user requested
    """
    headers = {
        'Authorization': 'Bearer ' + scim_token
    }
    response = test_client.get(USER_PATH + '/' + scim_user['id'], headers=headers, content_type='application/json')
    assert response.status_code == 200
    assert response.headers['ETag'] == response.json['meta']['version']
    assert response.json['username'] == 'mcescher'
    assert response.json['active'] is True
    assert response.json['meta']['resourceType'] == 'User'
    assert response.json['meta']['location'] == 'https://localhost:5000/scim/v2/Users/' + response.json['id']


def test_scim_create_group(test_client, scim_client, scim_token):
    """
        GIVEN:  POST request to the /scim/v2/Groups endpoint
        WHEN:   Authorization header is valid
        THEN:   server responds with 201 Created and the representation of the group created
    """

    header = {
        'Authorization': 'Bearer ' + scim_token
    }
    data = {
        'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group'],
        'displayName': 'test_group'
    }
    response = test_client.post(GROUP_PATH, data=json.dumps(data), headers=header, content_type='application/json')
    assert response.status_code == 201
    assert response.headers['ETag'] == response.json['meta']['version']
    assert response.json['displayName'] == 'test_group'
    assert response.json['active'] is True
    assert response.json['meta']['resourceType'] == 'Group'
    assert response.json['meta']['location'] == 'https://localhost:5000/scim/v2/Groups/' + response.json['id']


def test_scim_get_group(test_client, scim_group, scim_token):
    """
        GIVEN:  GET request to the /scim/v2/Groups/<id> endpoint
        WHEN:   Authorization header is valid
        THEN:   server responds with 200 OK and the representation of the group requested
    """
    headers = {
        'Authorization': 'Bearer ' + scim_token
    }
    response = test_client.get(GROUP_PATH + '/' + scim_group['id'], headers=headers, content_type='application/json')
    assert response.status_code == 200
    assert response.headers['ETag'] == response.json['meta']['version']
    assert response.json['displayName'] == 'test_grp'
    assert response.json['meta']['resourceType'] == 'Group'
    assert response.json['meta']['location'] == 'https://localhost:5000/scim/v2/Groups/' + response.json['id']
