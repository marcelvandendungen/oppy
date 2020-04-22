import base64
from provider.model.token_request import TokenRequestError
import jwt
import requests
import os
import sys
import uuid
from jwcrypto import jwk
from urllib.parse import urlencode, quote
from util import init_logging, init_config

from flask import Flask, request, redirect, render_template
app = Flask(__name__)


config = init_config('config.yml')
logger = init_logging(__name__)
scopes = {}


class TokenStore:
    def __init__(self):
        self.tokens = {}

    def add(self, scope, token, type):
        self.tokens[(scope, type)] = token

    def get(self, scope, type):
        token = self.tokens.get((scope, type))
        return token


tokencache = TokenStore()


def get_public_key(url):
    response = requests.get(url, verify=False)
    key = jwk.JWK.from_json(response.content)
    return key.export_to_pem()


def register_client():

    url = "https://127.0.0.1:5000/register"
    headers = {
        'Content-Type': 'application/json'
    }
    payload = {
        "grant_types": ["authorization_code"],
        "redirect_uris": ["https://localhost:5001/cb", "https://localhost:5003/cb"],
        "name": "confidential_client",
        "scope": "read write openid"
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    return response.json()


public_key = get_public_key(config['endpoints']['issuer'] + '/jwk')
# read client id and secret from environment
client_id = os.environ.get('CLIENT_ID')
if client_id:
    client_secret = os.environ['CLIENT_SECRET']
    redirect_uri = os.environ['REDIRECT_URI']
else:
    # if not set, register client and use it's id and secret
    client = register_client()
    client_id = client['client_id']
    client_secret = client['client_secret']
    redirect_uri = client['redirect_uris'][0]


logger.info('client_id: ' + client_id)


@app.route("/")
def index():

    id_token = tokencache.get('openid', 'id_token')
    try:
        if id_token:
            logger.info('id_token found: ' + str(id_token))
            id_claims = get_token_claims(id_token, client_id)
        else:
            logger.info('id token not found')
            return authorize_request(client, scope='openid')
    except (jwt.ExpiredSignatureError, jwt.InvalidAudienceError) as ex:
        logger.warn('ID token expired: ', str(ex))
        return authorize_request(client, scope='openid')

    access_token = tokencache.get('read write', 'access_token')
    try:
        if access_token:
            logger.info('access token found: ' + access_token)
            response = requests.get('https://localhost:5002/resource',
                                    headers={'Authorization': 'Bearer ' + access_token},
                                    verify=False)
            if response.status_code == 200:
                return render_template('index.html', token=response.json(), name=id_claims['name'])
            elif response.status_code == 401:
                logger.info("Access token is expired, refreshing...")
                access_token = refresh_access_token('urn:my_service', 'read write')
                response = redirect('/')    # redirect to index page
                response.set_cookie('token', access_token, samesite='Lax')
                return response
        else:
            logger.info('access cookie not found')
            return authorize_request(client, scope='read write')

    except (jwt.ExpiredSignatureError, jwt.InvalidAudienceError, TokenRequestError):
        return authorize_request(client, scope='read write')


def authorize_request(client, scope):
    logger.info('Requesting token(s) with scope: ' + scope)
    state = str(uuid.uuid4())
    scopes[state] = scope
    return redirect(request_url('https://localhost:5000/authorize', client_id=client_id, redirect_uri=redirect_uri,
                                response_type='code', state=state, scope=scope, response_mode='form_post'))


def request_url(url, **query_params):
    return url + '?' + urlencode(query_params)


@app.route("/cb", methods=["GET", "POST"])
def auth_code():
    error = request.args.get('error')
    if error:
        return render_template('error.html', error=error)

    if request.method == 'GET':
        code = request.args.get('code')
        state = request.args.get('state')
    elif request.method == 'POST':
        code = request.form.get('code')
        state = request.form.get('state')

    logger.warning('code = ' + code)
    # get token using auth code
    get_tokens(code, state)
    # store access_token as cookie
    response = redirect('/')    # redirect to index page
    return response


def get_tokens(auth_code, state):

    scope = scopes[state]

    token_endpoint = 'https://localhost:5000/token'
    redirect_url = 'https://localhost:5001/cb'
    headers = {}
    headers['Content-Type'] = "application/x-www-form-urlencoded"
    headers['Authorization'] = authorization_header()

    data = {"grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": quote(redirect_url),
            "client_id": client_id}

    response = requests.post(token_endpoint, headers=headers, data=data, verify=False)
    if response.status_code == 200:
        access_token = response.json()["access_token"]
        logger.info('access_token: ' + access_token)
        tokencache.add(scope, access_token, 'access_token')
        refresh_token = response.json().get("refresh_token")
        if refresh_token:
            logger.info('refresh_token: ' + refresh_token)
            tokencache.add(scope, access_token, 'refresh_token')
        id_token = response.json().get("id_token")
        if id_token:
            logger.info('id_token: ' + id_token)
            tokencache.add(scope, id_token, 'id_token')
    else:
        raise TokenRequestError()


def refresh_access_token(audience, scope):

    refresh_token = tokencache.get(audience, 'refresh_token')

    if not refresh_token:
        raise TokenRequestError()

    token_endpoint = 'https://localhost:5000/token'
    headers = {
        'Content-Type': "application/x-www-form-urlencoded",
        'Authorization': authorization_header()
    }

    data = {
        "grant_type": "refresh_token",
        "refresh_token": scope
    }

    response = requests.post(token_endpoint, headers=headers, data=data, verify=False)
    if response.status_code == 200:
        access_token = response.json()["access_token"]
        tokencache.add(scope, access_token, 'access_token')
        refresh_token = response.json().get('refresh_token')
        if refresh_token:
            tokencache.add(scope, refresh_token, 'refresh_token')
        return access_token

    raise TokenRequestError('Error refreshing token: ' + str(response))


def authorization_header():
    return 'Basic ' + base64.b64encode((client_id + ':' + client_secret).encode()).decode('utf-8')


def get_token_claims(token, audience):
    logger.info(token)
    claims = jwt.decode(str.encode(token), public_key, audience=audience, algorithms='RS256')
    return claims


def main():
    app.run(host='0.0.0.0', port=5001, debug=app.config['TESTING'],
            ssl_context=('cert.pem', 'key.pem'))


if __name__ == "__main__":
    sys.exit(main())
