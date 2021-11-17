# Client container image:

## The python "slim" image is lightweight compared to base python image or ubuntu image + python install.
## So far has been sufficient for our needs.
FROM python:3-slim as client

WORKDIR /client

COPY /client/client-db-init.py .
COPY /client/accesses-client-db.py .
COPY /client/client-schema.sql .

RUN pip3 install cryptography
RUN python3 client-db-init.py client-schema.sql


# Server container image:

FROM python:3-slim as kdc

WORKDIR /kdc

COPY /kdc/kdc-db-init.py .
COPY /kdc/kdc-schema.sql .

RUN python3 kdc-db-init.py kdc-schema.sql