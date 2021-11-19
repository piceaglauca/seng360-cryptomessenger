FROM ubuntu:20.04

# Set up Python
RUN apt-get update
RUN apt-get install -y python3.9
RUN apt-get install -y python3-pip

WORKDIR /code

# Install deps
RUN pip install --upgrade pip
COPY ./requirements.txt ./requirements.txt
RUN pip install -r ./requirements.txt

# Set up DB
COPY ./scripts/client-db-init.py ./scripts/client-db-init.py
COPY ./data/client-schema.sql ./data/client-schema.sql
RUN python3 ./scripts/client-db-init.py ./data/client-schema.sql

ENV LOG_LEVEL "DEBUG"
