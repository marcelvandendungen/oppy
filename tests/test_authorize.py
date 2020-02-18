"""
    These tests depend on 2 registered clients with ids: 'confidential_client' and 'public_client'
"""

import sys

def test_missing_client_id_results_in_error(test_client):
    """
        GIVEN:  GET request to the /authorize endpoint
        WHEN:   client_id query parameter is missing
        THEN:   response is 400 Bad Request
    """
    response = test_client.get('/authorize')
    assert response.status_code == 400

def test_invalid_redirect_uri_results_in_error(test_client):
    """
        GIVEN:  GET request to the /authorize endpoint
        WHEN:   redirect_uri query parameter does not match uri registered in client
        THEN:   response is 400 Bad Request
    """
    response = test_client.get('/authorize?client_id=confidential_client&response_type=code&redirect_uri=xyz')
    assert response.status_code == 400

def test_missing_response_type_results_in_redirect(test_client):
    """
        GIVEN:  GET request to the /authorize endpoint
        WHEN:   response_type query parameter is missing
        THEN:   response is 302 Redirect with error query parameter
    """
    response = test_client.get('/authorize?client_id=confidential_client&redirect_uri=http%3A%2F%2Flocalhost%3A5001%2Fcb&state=96f07e0b-992a-4b5e-a61a-228bd9cfad35')
    assert response.status_code == 302

def test_state_in_request_is_reflected_in_response(test_client):
    """
        GIVEN:  GET request to the /authorize endpoint
        WHEN:   state query parameter is specified
        THEN:   response is 200 OK with state as hidden input field in the HTML
    """
    response = test_client.get('/authorize?client_id=confidential_client&redirect_uri=http%3A%2F%2Flocalhost%3A5001%2Fcb&response_type=code&state=96f07e0b-992a-4b5e-a61a-228bd9cfad35')
    assert response.status_code == 200
    assert '96f07e0b-992a-4b5e-a61a-228bd9cfad35' in str(response.data)


def test_confidential_client_without_code_challenge_results_in_error(test_client):
    """
        GIVEN:  GET request to the /authorize endpoint
        WHEN:   client_id identifies a public client and code_challenge query parameter is missing
        THEN:   response is 302 Redirect with error query parameter (PKCE required for public clients)
    """
    response = test_client.get('/authorize?client_id=public_client&redirect_uri=http%3A%2F%2Flocalhost%3A5002%2Fcb&response_type=code&state=96f07e0b-992a-4b5e-a61a-228bd9cfad35')
    assert response.status_code == 302
