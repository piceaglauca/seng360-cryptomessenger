FROM ubuntu:20.04

# Set up Python
RUN apt-get update && apt-get install -y \
    python3.9 \
    python3-pip

WORKDIR /code

# Install deps
COPY ./requirements.txt ./requirements.txt
RUN pip install --upgrade pip && pip install -r ./requirements.txt

# Set up DB
COPY ./scripts/client-db-init.py ./scripts/client-db-init.py
COPY ./data/client-schema.sql ./data/client-schema.sql
RUN python3 ./scripts/client-db-init.py ./data/client-schema.sql

ENV LOG_LEVEL "DEBUG"
