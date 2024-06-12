#!/bin/bash

# Function to configure docker files
configure_docker() {
    # Device
    cat docker/Dockerfile-base.txt > docker/Dockerfile.device
    cat <<EOL >> docker/Dockerfile.device


ENTRYPOINT ["java", "-cp", "/app/resources/ntru-1.2.jar:/app/resources/ntrureencrypt-1.0.1.jar:/app/osre-1.0.1.jar", "nics.crypto.osre.MainOSREDevice", "$N", "8080"]
EOL
    # Owner
    cat docker/Dockerfile-base.txt > docker/Dockerfile.owner
    cat <<EOL >> docker/Dockerfile.owner


ENTRYPOINT ["java", "-cp", "/app/resources/ntru-1.2.jar:/app/resources/ntrureencrypt-1.0.1.jar:/app/osre-1.0.1.jar", "nics.crypto.osre.MainOSREOwner", "$N", "8080"]
EOL
    # Proxy
    cat docker/Dockerfile-base.txt > docker/Dockerfile.proxy
    cat <<EOL >> docker/Dockerfile.proxy


ENTRYPOINT ["java", "-cp", "/app/resources/ntru-1.2.jar:/app/resources/ntrureencrypt-1.0.1.jar:/app/osre-1.0.1.jar", "nics.crypto.osre.MainOSREProxy", "$N", "8080"]
EOL
    # Holder
    cat docker/Dockerfile-base.txt > docker/Dockerfile.holder
    cat <<EOL >> docker/Dockerfile.holder


ENTRYPOINT ["java", "-cp", "/app/resources/ntru-1.2.jar:/app/resources/ntrureencrypt-1.0.1.jar:/app/osre-1.0.1.jar", "nics.crypto.osre.MainOSREHolder", "$N", "8080"]
EOL

echo Dockerfiles correctly generated.
}

# Function to configure docker-compose file
configure_compose() {
REPLICAS=$N

# Validate the number of replicas is a positive integer
if ! [[ "$REPLICAS" =~ ^[0-9]+$ ]] || [ "$REPLICAS" -le 0 ]; then
    echo "The number of replicas must be a positive integer."
    exit 1
fi

# Start the docker-compose.yml content
cat <<EOL > ./docker/docker-compose.yml
version: '3.8'

services:
  osre-owner:
    image: osre-owner
    build:
      context: ..
      dockerfile: docker/Dockerfile.owner
    networks:
      - mynetwork
    depends_on:
      - osre-device
    ports:
      - "8080"

  osre-device:
    image: osre-device
    build:
      context: ..
      dockerfile: docker/Dockerfile.device
    networks:
      - mynetwork
    ports:
      - "8080"

  osre-proxy:
    image: osre-proxy
    build:
      context: ..
      dockerfile: docker/Dockerfile.proxy
    networks:
      - mynetwork
    ports:
      - "8080"

EOL

# Loop to create each service
for ((i=1; i<=REPLICAS; i++))
do
cat <<EOL >> ./docker/docker-compose.yml
  osre-holder_$i:
    image: osre-holder
    container_name: osre-holder_$i
    build:
      context: ..
      dockerfile: docker/Dockerfile.holder
    networks:
      - mynetwork
    ports:
      - "8080"

EOL
done

# Add the network definition
cat <<EOL >> ./docker/docker-compose.yml
networks:
  mynetwork:
    driver: bridge
EOL

echo "docker-compose.yml generated successfully with $REPLICAS replicas."
}

# Function to clear containers
clear_containers() {
    echo "Clearing containers..."
    docker rm -vf $(docker ps -aq)
    docker rmi -f $(docker images -aq)
}

# Function to configure files
configure_files() {
    echo "Configuring files..."
    configure_docker
    configure_compose
}

# Function to build files
build_files() {
    echo "Building files..."
    docker build -f ./docker/Dockerfile.owner -t osre-owner .
    docker build -f ./docker/Dockerfile.device -t osre-device .
    docker build -f ./docker/Dockerfile.proxy -t osre-proxy .
    docker build -f ./docker/Dockerfile.holder -t osre-holder .
}

# Function to execute containers
execute_containers() {
    echo "Executing containers with N=$1..."
    docker-compose -f docker/docker-compose.yml up --build
}

# Check if the correct number of arguments are provided
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <number_of_replicas> <options>"
    echo "Options: -c (clear), -f (configure), -b (build), -e (execute)"
    exit 1
fi

# Assign the first argument to N
N=$1

# Shift the arguments to parse options
shift

# Loop through options and execute the corresponding tasks in the specified order
while getopts "cfbe" opt; do
    case $opt in
        c)
            clear_containers
            ;;
        f)
            configure_files
            ;;
        b)
            build_files
            ;;
        e)
            execute_containers $N
            ;;
        *)
            echo "Invalid option: -$OPTARG" >&2
            echo "Usage: $0 <number_of_replicas> <options>"
            echo "Options: -c (clear), -f (configure), -b (build), -e (execute)"
            exit 1
            ;;
    esac
done

echo "Tasks completed."
