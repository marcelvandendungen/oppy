FROM python:3.7.7-stretch
# FROM python:3.8-alpine

WORKDIR /app

COPY . /app/provider

RUN pip3 --no-cache-dir install -r provider/requirements.txt

ENV PYTHONPATH="/app:/app/provider"

EXPOSE 5000

ENTRYPOINT ["python3"]
# CMD ["-u", "provider/app.py"]
