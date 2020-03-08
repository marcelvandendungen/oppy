import os
import sys

from flask import Flask
from oppy.endpoints.authorize.authorize import create_blueprint as create_authorize_bp
from oppy.endpoints.token.token import create_blueprint as create_token_blueprint

# default test clients
clients = [{
    'client_id': 'confidential_client',
    # redirect_uris must be absolute URLs, may contain query params, may not contain fragment
    'redirect_uris': ['http://localhost:5001/cb'],
    'public': False
}, {
    'client_id': 'public_client',
    'redirect_uris': ['http://localhost:5002/cb'],
    'public': True
}]


def read_pem(filename):
    with open(filename, "rb") as f1:
        key = f1.read()
        return key


def init_crypto():
    """
      Read private and public key from PEM file on disk
    """
    if not os.path.exists("./private.pem"):
        raise IOError("private.pem not found or no permission to read")
    private_key = read_pem("./private.pem")
    if not os.path.exists("./public.pem"):
        raise IOError("public.pem not found or no permission to read")
    else:
        public_key = read_pem("./public.pem")

    return private_key, public_key


keypair = init_crypto()
app = Flask(__name__)
# app.config['EXPLAIN_TEMPLATE_LOADING'] = True
app.config['TESTING'] = os.environ.get('TESTING') == 'True'
app.register_blueprint(create_authorize_bp(clients))
app.register_blueprint(create_token_blueprint(clients, keypair))


def main():
    print('running main')
    app.run(host='0.0.0.0', port=5000, debug=app.config['TESTING'])


if __name__ == "__main__":
    sys.exit(main())
