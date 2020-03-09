def test_jwk_endpoint_returns_valid_key(test_client):
    response = test_client.get('/jwk')
    assert response.status_code == 200
    assert response.json['kty'] == 'RSA'
    assert response.json['kid']
    assert response.json['e']
    assert response.json['n']
