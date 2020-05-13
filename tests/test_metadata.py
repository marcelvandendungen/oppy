

def test_metadata_endpoint_returns_valid_configuration(test_client):

    response = test_client.get('/.well-known/openid-configuration')
    assert response.status_code == 200
    assert response.json['authorization_endpoint'] == "https://localhost:5000/authorize"
    assert response.json['token_endpoint'] == "https://localhost:5000/token"
    assert response.json['userinfo_endpoint'] == "https://localhost:5000/userinfo"
    assert response.json['issuer'] == "https://localhost:5000"
    assert response.json['jwks_uri'] == "https://localhost:5000/jwk"
    assert response.json['registration_endpoint'] == "https://localhost:5000/register"

    assert set(response.json['grant_types_supported']) == set(["authorization_code", "client_credentials"])
    assert set(response.json['response_modes_supported']) == set(["query", "form_post"])
    assert set(response.json['response_types_supported']) == set(["code", "code id_token"])
    assert set(response.json['scopes_supported']) == set(["openid", "profile", "roles", "email", "read", "write"])
