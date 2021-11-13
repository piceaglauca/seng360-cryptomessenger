# crypticmessenger

To deploy, run from base directory:

_docker-compose up -d_

To check that containers are running:

_docker ps -a_

To get a shell on a container:

_docker exec -it container_name sh_

In client containers, "accesses-client-db.py" is an example script which performs queries on the client db initialized during container construction.



