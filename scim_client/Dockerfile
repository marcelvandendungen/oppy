FROM python:3.8-alpine

WORKDIR /app

COPY requirements.txt /app/scim_client/requirements.txt

RUN apk --update add python py-pip openssl ca-certificates py-openssl wget
RUN apk --update add --virtual build-dependencies libffi-dev openssl-dev python-dev py-pip build-base \
  && pip install --upgrade pip \
  && pip3 --no-cache-dir install -r scim_client/requirements.txt \
  && apk del build-dependencies

COPY . /app/scim_client

ENV PYTHONPATH="/app"

EXPOSE 5001

ENTRYPOINT ["python3"]
CMD ["-u", "scim_client/client.py"]
