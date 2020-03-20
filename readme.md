# OPPY

An OpenID Connect Provider and OAuth2 authorization server in Python Flask

Please DO NOT USE IN PRODUCTION!

This application is just a playground for me to explore identity protocols. This application is not hardened or tested to be used in a production environment.

## Run app instructions

```bash
#!/bin/bash
$ cd oppy
$ openssl genrsa -out private.pem 2048
$ openssl rsa -in private.pem -outform PEM -pubout -out public.pem
$ export FLASK_APP=provider/app.py
$ export FLASK_ENV=development
$ export FLASK_DEBUG=1
$ python -m flask run
# OR
$ python -m provider
# OR
$ python -m resource_server
```

## Run test instructions

```bash
#!/bin/bash
$ pytest [-v]
```
