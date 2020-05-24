import base64
import collections
import jwt
import requests
import os
import sys
import uuid
from jwcrypto import jwk
from urllib.parse import urlencode, quote
from util import init_logging, init_config
from oidcpy.crypto import read_keys

from flask import Flask, request, redirect, render_template
app = Flask(__name__)


config = init_config('webclient/config.yml')
logger = init_logging(__name__)
scopes = {}


_, public_key = read_keys("./private.pem", "./public.pem")

JKWS_ENDPOINT = config['endpoints']['issuer'] + config['endpoints']['jwks']
TOKEN_ENDPOINT = config['endpoints']['issuer'] + config['endpoints']['token']
AUTHORIZE_ENDPOINT = config['endpoints']['issuer'] + config['endpoints']['authorize']
REGISTRATION_ENDPOINT = config['endpoints']['issuer'] + config['endpoints']['registration']
RESOURCE_ENDPOINT = config['endpoints']['resource_server'] + config['endpoints']['resource']
USERINFO_ENDPOINT = config['endpoints']['issuer'] + config['endpoints']['userinfo']


class TokenError(Exception):
    pass


class TokenStore:
    def __init__(self):
        "key = state, value = list of tuples, each with of list of scopes, type and token"
        self.tokens = collections.defaultdict(list)

    def add(self, state, scope, token, type):
        print(f'add {type} for {scope}')
        self.tokens[state].append((scope.split(' '), type, token))

    def get(self, state, scope, type):
        states = state.split(' ')   # multiple space separated states are allowed
        for s in states:
            print(f'get {type} for {s} with {scope}')
            items = self.tokens[s]
            for item in items:
                # iterate through list of tuples
                # find one with right scope(s) and correct type
                if set(scope.split(' ')).issubset(set(item[0])) and type == item[1]:
                    return item[2]

        return None


tokencache = TokenStore()


def get_public_key(url):
    response = requests.get(url, verify=False)
    key = jwk.JWK.from_json(response.content)
    return key.export_to_pem()


def register_client(config):

    url = REGISTRATION_ENDPOINT
    headers = {
        'Content-Type': 'application/json'
    }
    payload = {
        "grant_types": ["authorization_code"],
        "redirect_uris": ["https://localhost:5001/cb", "https://localhost:5003/cb"],
        "name": "confidential_client",
        "scope": "read write openid profile email roles"
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    return response.json()


public_key = get_public_key(JKWS_ENDPOINT)
# read client id and secret from environment
client_id = os.environ.get('CLIENT_ID')
if client_id:
    client_secret = os.environ['CLIENT_SECRET']
    redirect_uri = os.environ['REDIRECT_URI']
else:
    # if not set, register client and use it's id and secret
    client = register_client(config)
    client_id = client['client_id']
    client_secret = client['client_secret']
    redirect_uri = client['redirect_uris'][0]


logger.info(f'Registered client with client_id: {client_id}')


@app.route("/")
def index():

    session_cookie = request.cookies.get('auth')

    if not session_cookie:
        return authorize_request(client, scope='openid profile email roles')
    else:
        state = session_cookie

    userinfo_claims = {}
    id_token = tokencache.get(state, 'openid', 'id_token')
    try:
        if id_token:
            logger.info('id_token found: ' + str(id_token))
            id_claims = get_token_claims(id_token, client_id)

            access_token = tokencache.get(state, 'openid', 'access_token')
            response = requests.get(USERINFO_ENDPOINT, headers={'Authorization': 'Bearer ' + access_token},
                                    verify=False)
            if response.status_code == 200:
                userinfo_claims = response.json()
        else:
            logger.info('id token not found')
            return authorize_request(client, scope='openid profile email roles')
    except (jwt.ExpiredSignatureError, jwt.InvalidAudienceError) as ex:
        logger.warn('ID token expired: ', str(ex))
        return authorize_request(client, scope='openid')

    access_token = tokencache.get(state, 'read write', 'access_token')
    try:
        if access_token:
            logger.info('access token found: ' + access_token)
            response = requests.get(RESOURCE_ENDPOINT, headers={'Authorization': 'Bearer ' + access_token},
                                    verify=False)
            if response.status_code == 200:
                return render_template('index.html', token=response.json(), userinfo=userinfo_claims,
                                       name=id_claims['name'])
            elif response.status_code == 401:
                logger.info("Access token is expired, refreshing...")
                access_token = refresh_access_token(state, 'urn:my_service', 'read write')
                response = redirect('/')    # redirect to index page
                response.set_cookie('token', access_token, samesite='Lax')
                return response
        else:
            logger.info('access cookie not found')
            return authorize_request(client, scope='read write')

    except (jwt.ExpiredSignatureError, jwt.InvalidAudienceError, TokenError):
        return authorize_request(client, scope='read write')


def authenticated_session(token):
    try:
        if not token:
            logger.info("Session cookie not found")
            return None
        claims = jwt.decode(str.encode(token), public_key, audience='https://localhost:5000', algorithms='RS256')
        logger.info("Session cookie is valid")
        return claims
    except jwt.ExpiredSignatureError:
        logger.info("Session cookie expired")
        return None


def authorize_request(client, scope):
    logger.info('Requesting token(s) with scope: ' + scope)
    state = str(uuid.uuid4())
    scopes[state] = scope
    return redirect(request_url(AUTHORIZE_ENDPOINT, client_id=client_id,
                                redirect_uri=redirect_uri, response_type='code', state=state, scope=scope,
                                response_mode='form_post'))


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

    cookie = request.cookies.get('auth', '')

    logger.warning('code = ' + code)
    # get token using auth code
    get_tokens(code, state)
    # store access_token as cookie
    response = redirect('/')    # redirect to index page
    response.set_cookie('auth', ' '.join([s for s in [cookie, state] if len(s) > 0]))
    return response


def get_tokens(auth_code, state):

    scope = scopes[state]

    redirect_url = 'https://localhost:5001/cb'
    headers = {}
    headers['Content-Type'] = "application/x-www-form-urlencoded"
    headers['Authorization'] = authorization_header()

    data = {"grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": quote(redirect_url),
            "client_id": client_id}

    response = requests.post(TOKEN_ENDPOINT, headers=headers, data=data, verify=False)
    if response.status_code == 200:
        access_token = response.json()["access_token"]
        logger.info('access_token: ' + access_token)
        tokencache.add(state, scope, access_token, 'access_token')
        refresh_token = response.json().get("refresh_token")
        if refresh_token:
            logger.info('refresh_token: ' + refresh_token)
            tokencache.add(state, scope, refresh_token, 'refresh_token')
        id_token = response.json().get("id_token")
        if id_token:
            logger.info('id_token: ' + id_token)
            tokencache.add(state, scope, id_token, 'id_token')
    else:
        raise TokenError()


def refresh_access_token(subject, audience, scope):

    refresh_token = tokencache.get(subject, audience, 'refresh_token')

    if not refresh_token:
        raise TokenError()

    headers = {
        'Content-Type': "application/x-www-form-urlencoded",
        'Authorization': authorization_header()
    }

    data = {
        "grant_type": "refresh_token",
        "refresh_token": scope
    }

    response = requests.post(TOKEN_ENDPOINT, headers=headers, data=data, verify=False)
    if response.status_code == 200:
        access_token = response.json()["access_token"]
        tokencache.add(subject, scope, access_token, 'access_token')
        refresh_token = response.json().get('refresh_token')
        if refresh_token:
            tokencache.add(subject, scope, refresh_token, 'refresh_token')
        return access_token

    raise TokenError('Error refreshing token: ' + str(response))


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
