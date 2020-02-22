import sys

from flask import Flask
from oppy.endpoints.authorize.authorize import create_blueprint as create_authorize_bp
from oppy.endpoints.token.token import create_blueprint as create_token_blueprint

# default test clients
clients = [{
    'client_id': 'confidential_client',
    'redirect_uris': ['http://localhost:5001/cb'], # must be absolute URL, may contain query params, must not contain fragment
    'public': False
},
{
    'client_id': 'public_client',
    'redirect_uris': ['http://localhost:5002/cb'],
    'public': True
}]


app = Flask(__name__)
# app.config['EXPLAIN_TEMPLATE_LOADING'] = True
app.config['TESTING'] = True
app.register_blueprint(create_authorize_bp(app.config['TESTING'], clients))
app.register_blueprint(create_token_blueprint(app.config['TESTING'], clients))

def main():
    print('running main')
    app.run(host='0.0.0.0', port=5000, debug=True)


if __name__ == "__main__":
    sys.exit(main())
