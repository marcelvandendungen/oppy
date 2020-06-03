FROM python:3.8-alpine

WORKDIR /app

COPY requirements.txt /app/provider/requirements.txt

RUN apk --update add python py-pip openssl ca-certificates py-openssl wget
RUN apk --update add --virtual build-dependencies libffi-dev openssl-dev python-dev py-pip build-base \
  && pip install --upgrade pip \
  && pip3 --no-cache-dir install -r provider/requirements.txt \
  && apk del build-dependencies

COPY . /app/provider

ENV PYTHONPATH="/app"
ENV KEY_LOCATION="provider/public.pem"
ENV LOG_PATH="/app/provider/log/log.txt"

EXPOSE 5000

ENTRYPOINT ["python3"]
CMD ["-u", "provider/__main__.py", "--config=provider/docker_config.yml"]
