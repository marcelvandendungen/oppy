import sys

def test_token_endpoint_can_be_called(test_client):
    response = test_client.get('/token')
    assert response.status_code == 200
