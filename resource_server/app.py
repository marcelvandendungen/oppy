from base64 import encode
import jwt
import os
import sys

from flask import Flask, request


app = Flask(__name__)
app.config['TESTING'] = os.environ.get('TESTING') == 'True'


def read_pem(filename):
    with open(filename, "rb") as f1:
        key = f1.read()
        return key


public_key = read_pem("./public.pem")


@app.route('/resource')
def resource():
    try:
        auth_header = request.headers['Authorization']
        user = validate(auth_header[7:], audience='urn:my_service', scopes='read')
        return str(user)
    except KeyError as ex:
        return str(ex)


def validate(token, audience, scopes):
    claims = jwt.decode(str.encode(token), public_key, audience=audience, algorithm=['RS256'])
    return claims['userid']


def main():
    print('running resource server')
    app.run(host='0.0.0.0', port=5001, debug=app.config['TESTING'])


if __name__ == "__main__":
    sys.exit(main())
