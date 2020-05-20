# FROM python:3.7.7-stretch
FROM python:3.8-alpine

WORKDIR /app

COPY . /app/resource_server

RUN apk --update add python py-pip openssl ca-certificates py-openssl wget
RUN apk --update add --virtual build-dependencies libffi-dev openssl-dev python-dev py-pip build-base \
  && pip install --upgrade pip \
  && pip3 --no-cache-dir install -r resource_server/requirements.txt \
  && apk del build-dependencies

# RUN pip3 --no-cache-dir install -r resource_server/requirements.txt

ENV PYTHONPATH="/app"
ENV KEY_LOCATION="https://localhost:5000/jwk"

EXPOSE 5002

ENTRYPOINT ["python3"]
CMD ["-u", "resource_server/app.py"]
