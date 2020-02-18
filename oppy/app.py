import sys

from flask import Flask
from oppy.endpoints.authorize.authorize import authorize_bp
from oppy.endpoints.token.token import token_bp

app = Flask(__name__)
# app.config['EXPLAIN_TEMPLATE_LOADING'] = True
app.config['TESTING'] = True
app.register_blueprint(authorize_bp)
app.register_blueprint(token_bp)

def main():
    print('running main')
    app.run(host='0.0.0.0', port=5000, debug=True)


if __name__ == "__main__":
    sys.exit(main())
