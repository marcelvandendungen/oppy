
def test_userinfo_endpoint_returns_valid_claims(test_client, usertoken):
    header = {
        'Authorization': 'Bearer ' + usertoken
    }
    response = test_client.get('/userinfo', headers=header)
    assert response.status_code == 200
    assert response.json['name'] == 'Test User'
    assert response.json['sub'] == 'testuser'
