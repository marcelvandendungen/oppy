import sys

def test_authorize_endpoint_can_be_called(test_client):
    response = test_client.get('/authorize')
    assert response.status_code == 200
