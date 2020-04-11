import base64
import jwt
import requests
import os
import sys
from jwcrypto import jwk
from urllib.parse import urlencode, quote
from util import init_logging, init_config

from flask import Flask, request, redirect, render_template
app = Flask(__name__)


config = init_config('config.yml')
logger = init_logging(__name__)

refresh_token = None


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
    return response.json()['client_id'], response.json()['client_secret']


public_key = get_public_key(config['endpoints']['issuer'] + '/jwk')
# read client id and secret from environment
client_id = os.environ.get('CONFIDENTIAL_CLIENT_ID')
if client_id:
    client_secret = os.environ['CONFIDENTIAL_CLIENT_SECRET']
else:
    # if not set, register client and use it's id and secret
    client_id, client_secret = register_client()

logger.info('client_id: ' + client_id)


@app.route("/")
def index():
    cookie = request.cookies.get('token')
    if cookie:
        id_claims = get_token_claims(request.cookies.get('id_token'))

        logger.info('cookie: ' + cookie)
        response = requests.get('https://localhost:5002/resource',
                                headers={'Authorization': 'Bearer ' + cookie},
                                verify=False)
        if response.status_code == 200:
            return render_template('index.html', token=response.json(), name=id_claims['name'])
        elif response.status_code == 401:
            logger.info("token is expired, refreshing...")
            try:
                access_token = refresh_access_token()
                response = redirect('/')    # redirect to index page
                response.set_cookie('token', access_token)
                return response
            except Exception:
                logger.exception("Exception occurred")
                pass    # default to new authorization request
        else:
            logger.warn("Response from resource server: " + str(response.status_code))

    # client id should be set in the environment
    return redirect(authorize_request('https://localhost:5000/authorize', client_id=client_id,
                    redirect_uri='https://localhost:5001/cb', response_type='code',
                    state='96f07e0b-992a-4b5e-a61a-228bd9cfad35', scope='read write openid'))


def authorize_request(url, **query_params):
    return url + '?' + urlencode(query_params)


@app.route("/cb")
def auth_code():
    code = request.args.get('code')
    logger.warning('code = ' + code)
    # get token using auth code
    access_token, id_token = get_tokens(code)
    logger.info(access_token)
    # store access_token as cookie
    response = redirect('/')    # redirect to index page
    response.set_cookie('token', access_token)
    response.set_cookie('id_token', id_token)
    return response


def get_tokens(auth_code):
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

    global refresh_token
    refresh_token = response.json()["refresh_token"]

    return response.json()["access_token"], response.json()["id_token"]


def refresh_access_token():
    token_endpoint = 'https://localhost:5000/token'
    headers = {
        'Content-Type': "application/x-www-form-urlencoded",
        'Authorization': authorization_header()
    }

    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }

    response = requests.post(token_endpoint, headers=headers, data=data, verify=False)
    if response.status_code == 200:
        return response.json()["access_token"]

    raise RuntimeError('Error refreshing token')


def authorization_header():
    return 'Basic ' + base64.b64encode((client_id + ':' + client_secret).encode()).decode('utf-8')


def get_token_claims(id_token):
    claims = jwt.decode(str.encode(id_token), public_key,
                        audience=client_id, algorithm=['RS256'])
    return claims


def main():
    app.run(host='0.0.0.0', port=5001, debug=app.config['TESTING'],
            ssl_context=('cert.pem', 'key.pem'))


if __name__ == "__main__":
    sys.exit(main())
