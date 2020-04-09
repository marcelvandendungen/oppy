# OPPY

An OpenID Connect Provider and OAuth2 authorization server in Python Flask

Please DO NOT USE IN PRODUCTION!

This application is just a playground for me to explore identity protocols. This application is not hardened or tested to be used in a production environment.

## Run app instructions

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
$ python -m provider
$ python -m resource_server
$ python -m webclient
```

## Run test instructions

```bash
#!/bin/bash
$ pytest [-v]
```
