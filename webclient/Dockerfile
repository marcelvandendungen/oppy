FROM python:3.8-alpine

WORKDIR /app

COPY requirements.txt /app/webclient/requirements.txt

RUN apk --update add python py-pip openssl ca-certificates py-openssl wget
RUN apk --update add --virtual build-dependencies libffi-dev openssl-dev python-dev py-pip build-base \
  && pip install --upgrade pip \
  && pip3 --no-cache-dir install -r webclient/requirements.txt \
  && apk del build-dependencies

COPY . /app/webclient

ENV PYTHONPATH="/app"
ENV KEY_LOCATION="https://provider:5000/jwk"

EXPOSE 5001

ENTRYPOINT ["python3"]
CMD ["-u", "webclient/app.py"]
