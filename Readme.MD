Docker build on local:
docker build -t <image_name>:<tag> .
docker container run --publish <port>:<port> --name <container_name> <imagename>:<tag>