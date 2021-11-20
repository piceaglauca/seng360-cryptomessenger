FROM ubuntu:20.04

# Set up Python
RUN apt-get update && apt-get install -y \
    python3.9 \
    python3-pip

WORKDIR /code

# Install deps
COPY ./requirements.txt ./requirements.txt
RUN pip install -r ./requirements.txt && pip install --upgrade pip

# Set up DB
COPY ./scripts/kdc-db-init.py ./scripts/kdc-db-init.py
COPY ./data/kdc-schema.sql ./data/kdc-schema.sql
RUN python3 ./scripts/kdc-db-init.py ./data/kdc-schema.sql

ENV LOG_LEVEL "DEBUG"

# Start server
CMD ["uvicorn", "kdc:APP", "--host", "kdc", "--port", "8000"]
