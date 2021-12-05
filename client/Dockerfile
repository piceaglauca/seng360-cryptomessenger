FROM ubuntu:20.04

ENV TZ=America/Vancouver
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Set up Python
RUN apt-get update && apt-get install -y \
    python3.9 \
    python3-pip

WORKDIR /code/client

# Install deps
COPY ./requirements.txt ./requirements.txt
RUN pip install --upgrade pip && pip install -r ./requirements.txt

# Set up DB
COPY ./scripts/client-db-init.py ./scripts/client-db-init.py
COPY ./data/client-schema.sql ./data/client-schema.sql
RUN python3 ./scripts/client-db-init.py ./data/client-schema.sql

ENV LOG_LEVEL "DEBUG"

CMD ["sh", "./scripts/startup.sh"]
