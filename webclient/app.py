import base64
import collections
import jwt
import logging
import requests
import os
import sys
import uuid
import yaml
from jwcrypto import jwk
from urllib.parse import urlencode, quote
from oidcpy.crypto import read_keys

from flask import Flask, request, redirect, make_response, render_template
app = Flask(__name__)


def init_logging(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    filepath = os.getenv('LOG_PATH')
    if filepath:
        logging.basicConfig(filename=filepath, filemode='a',
                            format='%(asctime)s - %(message)s', level=logging.INFO)
    else:
        logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
    return logger


def init_config(path):
    config = yaml.load(open(path, 'r'), Loader=yaml.FullLoader)
    return config


logger = None
scopes = {}
client = None


_, public_key = read_keys("./webclient/private.pem", "./webclient/public.pem")


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

    url = app.config.get('REGISTRATION_ENDPOINT')
    headers = {
        'Content-Type': 'application/json'
    }
    payload = {
        "grant_types": ["authorization_code"],
        "redirect_uris": ["https://localhost:5001/cb", "https://localhost:5003/cb"],
        "name": "confidential_client",
        "scope": "read write openid profile email roles",
        "frontchannel_logout_uri": "https://localhost:5001/logout",
        "post_logout_redirect_uris": [app.config.get('POST_LOGOUT_URI')]
    }

    response = requests.post(url, headers=headers, json=payload, verify=False)
    return response.json()


@app.route("/")
def index():

    session_cookie = request.cookies.get('auth')

    if not session_cookie:
        logger.info("No session cookie found, authorizing.")
        return authorize_request(client, scope='openid profile email roles')
    else:
        logger.info("Session cookie found.")
        state = session_cookie

    userinfo_claims = {}
    id_token = tokencache.get(state, 'openid', 'id_token')
    try:
        if id_token:
            logger.info('id_token found: ' + str(id_token))
            id_claims = get_token_claims(id_token, client['client_id'], public_key)

            access_token = tokencache.get(state, 'openid', 'access_token')
            response = requests.get(app.config.get('USERINFO_ENDPOINT'),
                                    headers={'Authorization': 'Bearer ' + access_token}, verify=False)
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
            response = requests.get(app.config.get('RESOURCE_ENDPOINT'), 
                                    headers={'Authorization': 'Bearer ' + access_token}, verify=False)
            if response.status_code == 200:
                logout_url = request_url(app.config.get('LOGOUT_URI'), 
                                         post_logout_redirect_uri=app.config.get('POST_LOGOUT_URI'),
                                         state=str(uuid.uuid4()), id_token_hint=id_token)
                return render_template('index.html', token=response.json(), userinfo=userinfo_claims,
                                       name=id_claims['name'], logout_url=logout_url)
            elif response.status_code == 401:
                logger.info("Access token is expired, refreshing...")
                access_token = refresh_access_token(state, 'urn:my_service', 'read write')
                response = redirect('/')    # redirect to index page
                return response
            else:
                logger.warn(f'error from userinfo endpoint: {response.status_code}')
        else:
            logger.info('access cookie not found')
            return authorize_request(client, scope='read write')

    except (jwt.ExpiredSignatureError, jwt.InvalidAudienceError, TokenError):
        return authorize_request(client, scope='read write')


@app.route("/logout")
def logout():
    resp = make_response('')    # make empty response that clears cookies
    resp.set_cookie('auth', '', expires=0)
    return resp, 204


@app.route("/logged_out")
def logged_out():
    return render_template('post_logout.html')


def authorize_request(client, scope):
    client_id = client['client_id']
    logger.info(f'Authorize request with scope: {scope} for client {client_id}')
    state = str(uuid.uuid4())
    scopes[state] = scope
    return redirect(request_url(app.config.get('AUTHORIZE_ENDPOINT'), client_id=client_id,
                                redirect_uri=client['redirect_uri'], response_type='code', state=state, scope=scope,
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
    headers['Authorization'] = authorization_header(client)

    data = {"grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": quote(redirect_url),
            "client_id": client['client_id']}

    response = requests.post(app.config.get('TOKEN_ENDPOINT'), headers=headers, data=data, verify=False)
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
        'Authorization': authorization_header(client)
    }

    data = {
        "grant_type": "refresh_token",
        "refresh_token": scope
    }

    response = requests.post(app.config.get('TOKEN_ENDPOINT'), headers=headers, data=data, verify=False)
    if response.status_code == 200:
        access_token = response.json()["access_token"]
        tokencache.add(subject, scope, access_token, 'access_token')
        refresh_token = response.json().get('refresh_token')
        if refresh_token:
            tokencache.add(subject, scope, refresh_token, 'refresh_token')
        return access_token

    raise TokenError('Error refreshing token: ' + str(response))


def authorization_header(client):
    return 'Basic ' + base64.b64encode((client['client_id'] + ':' + client['client_secret']).encode()).decode('utf-8')


def get_token_claims(token, audience, public_key):
    logger.info(token)
    claims = jwt.decode(str.encode(token), public_key, audience=audience, algorithms='RS256')
    return claims


def main(config_path):
    global logger
    logger = init_logging(__name__)
    global client

    config = init_config(config_path)
    app.config['JKWS_ENDPOINT'] = config['endpoints']['issuer'] + config['endpoints']['jwks']
    app.config['TOKEN_ENDPOINT'] = config['endpoints']['issuer'] + config['endpoints']['token']
    app.config['AUTHORIZE_ENDPOINT'] = config['endpoints']['issuer'] + config['endpoints']['authorize']
    app.config['REGISTRATION_ENDPOINT'] = config['endpoints']['issuer'] + config['endpoints']['registration']
    app.config['RESOURCE_ENDPOINT'] = config['endpoints']['resource_server'] + config['endpoints']['resource']
    app.config['USERINFO_ENDPOINT'] = config['endpoints']['issuer'] + config['endpoints']['userinfo']
    app.config['POST_LOGOUT_URI'] = config['endpoints']['webclient'] + config['endpoints']['post_logout']
    app.config['LOGOUT_URI'] = config['endpoints']['issuer'] + config['endpoints']['logout']

    # read client id and secret from environment
    client_id = os.environ.get('CLIENT_ID')
    if client_id:
        client = {
            'client_id': client_id,
            'client_secret': os.environ['CLIENT_SECRET'],
            'redirect_uri': os.environ['REDIRECT_URI']
        }
    else:
        # if not set, register client and use it's id and secret
        registered_client = register_client(config)
        logger.info(registered_client)
        client = {
            'client_id': registered_client['client_id'],
            'client_secret': registered_client['client_secret'],
            'redirect_uri': registered_client['redirect_uris'][0]
        }
        logger.info(client)

    logger.info(f'Registered client with client_id: {client_id}')

    app.run(host='0.0.0.0', port=5001, debug=app.config['TESTING'],
            ssl_context=('webclient/cert.pem', 'webclient/key.pem'))


if __name__ == "__main__":
    sys.exit(main())
