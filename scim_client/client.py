import json
import sys
import requests
import yaml
from util import init_config


config = init_config('config.yml')


issuer = config['endpoints']['issuer']
config['endpoints']['registration']

REGISTER_PATH = config['endpoints']['issuer'] + config['endpoints']['registration']
TOKEN_PATH = config['endpoints']['issuer'] + config['endpoints']['token']
USER_PATH = config['endpoints']['issuer'] + config['endpoints']['scim'] + '/Users'


client_registration_payload = {
    'grant_types': [
        'client_credentials'
    ],
    'token_endpoint_auth_method': 'client_secret_basic',
    'name': 'provisioner',
    'scope': "create_user get_user create_group get_group"
}


def register_client():
    header = {
        'Content-Type': 'application/json'
    }
    response = requests.post(REGISTER_PATH, data=json.dumps(client_registration_payload),
                             headers=header, verify=False)
    if response.status_code == 201:
        return response.json()
    response.raise_for_status()


def get_token(scim_client):
    header = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'grant_type': 'client_credentials',
        'client_id': scim_client['client_id'],
        'client_secret': scim_client['client_secret']
    }
    response = requests.post(TOKEN_PATH, data=data, headers=header, verify=False)
    response.raise_for_status()
    print(response.json()['access_token'])
    return response.json()['access_token']


def register_user(user, token):
    header = {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
    }
    data = {
        'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
        'username': user['username'],
        'password': user['password'],
        'name': {
            'familyName': user['familyName']
        }
    }
    if 'givenName' in user:
        data['name']['givenName'] = user['givenName']
    if 'middleName' in user:
        data['name']['middleName'] = user['middleName']
    if 'roles' in user:
        data['roles'] = [{'value': role} for role in user['roles']]

    response = requests.post(USER_PATH, data=json.dumps(data), headers=header, verify=False)
    return response.json()


def main(args):
    scim_client = register_client()
    print(str(scim_client))
    token = get_token(scim_client)
    input_file = yaml.load(open('scim_client/users.yml', 'r'), Loader=yaml.FullLoader)
    for user in input_file['users']:
        register_user(user, token)
        print("creating user: ", user)


if __name__ == "__main__":
    main(sys.argv)
