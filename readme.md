# OPPY

An OpenID Connect Provider and OAuth2 authorization server in Python Flask

Please DO NOT USE IN PRODUCTION!

This application is just a playground for me to explore identity protocols. This application is not hardened or tested to be used in a production environment.

## Get Ready to Run App
1. Create a python virtual environment `virtualenv --python=python3 oppyvenv`
2. `source oppyvenv/bin/activate`
3. `pip install -r requirements.txt

## Run app locally

```bash
#!/bin/bash
$ cd oppy
# generate RSA private key
$ openssl genrsa -out private.pem 2048
# derive public key from private key
$ openssl rsa -in private.pem -outform PEM -pubout -out public.pem
# generate private key and certificate for TLS
$ openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
$ export FLASK_APP=provider/app.py
$ export FLASK_ENV=development
$ export FLASK_DEBUG=1
$ python -m flask run
# OR
$ export PYTHONPATH="$HOME/dev/oppy"
$ export TESTING=True
# export KEY_LOCATION="public.pem"
$ python -m provider
# export KEY_LOCATION="https://localhost:5000/jwk"
$ python -m resource_server
$ python -m webclient
```

## Run test instructions

```bash
#!/bin/bash
$ export PYTHONPATH="$HOME/dev/oppy"
$ export KEY_LOCATION="https://localhost:5000/jwk"
$ pytest [-v]
```

## Run app in Docker
```bash
#!/bin/bash
$ # add this line to hosts file at /etc/hosts
  # 127.0.0.1       provider
$ docker-compose up
```
