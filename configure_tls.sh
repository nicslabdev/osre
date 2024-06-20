#!/bin/bash

# Function to configure TLS certificates
configure_certs() {

./generateCerts.sh $N

}

# Function to configure docker files
configure_docker() {
	# Device
	cat docker/Dockerfile-base-tls.txt > docker/Dockerfile.tls-device
	cat <<EOL >> docker/Dockerfile.tls-device

ENTRYPOINT ["java", "-cp", "/app/resources/ntru-1.2.jar:/app/resources/ntrureencrypt-1.0.1.jar:/app/osre-1.0.1.jar", "nics.crypto.osre.MainTLSDevice", "$N", "$P", "$T", "172.28.0.2"]
EOL

	# Holder
	cat docker/Dockerfile-base-tls.txt > docker/Dockerfile.tls-holder
	cat <<EOL >> docker/Dockerfile.tls-holder
	
ENTRYPOINT ["java", "-cp", "/app/resources/ntru-1.2.jar:/app/resources/ntrureencrypt-1.0.1.jar:/app/osre-1.0.1.jar", "nics.crypto.osre.MainTLSHolder", "$N", "$P", "$T"]
CMD ["", ""]
EOL

echo Dockerfiles correctly generated.
}

# Function to configure docker-compose file
configure_compose() {
REPLICAS=$N
PORT=$P

# Validate the number of replicas is a positive integer
if ! [[ "$REPLICAS" =~ ^[0-9]+$ ]] || [ "$REPLICAS" -le 0 ]; then
    echo "The number of replicas must be a positive integer."
    exit 1
fi

# Start the docker-compose.yml content
cat <<EOL > ./docker/docker-compose-tls.yml
version: '3.8'

services:
  tls-device:
    image: tls-device
    build:
      context: ..
      dockerfile: docker/Dockerfile.tls-device
    networks:
      osre_network:
        ipv4_address: 172.28.0.2
    ports:
      - "$PORT"
    volumes:
      - log-data:/logs
    depends_on:
EOL


for ((i=1; i<=REPLICAS; i++))
do
cat <<EOL >> ./docker/docker-compose-tls.yml
      - tls-holder_$i
EOL
done

# Loop to create each service
for ((i=1; i<=REPLICAS; i++))
do
IP_TAIL=$((10 + i))
IP="172.28.0.$IP_TAIL"
cat <<EOL >> ./docker/docker-compose-tls.yml
  
  tls-holder_$i:
    image: tls-holder
    container_name: tls-holder_$i
    build:
      context: ..
      dockerfile: docker/Dockerfile.tls-holder
    networks:
      osre_network:
        ipv4_address: $IP
    ports:
      - "$PORT"
    volumes:
      - log-data:/logs
    command: ["$IP", "$i"]
EOL
done

# Add the network definition
cat <<EOL >> ./docker/docker-compose-tls.yml

networks:
  osre_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/24
    #name: osre_network
    #external: true
    
volumes:
  log-data:
    external: true
EOL

echo "docker-compose-tls.yml generated successfully with $REPLICAS replicas."
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
    docker build -f ./docker/Dockerfile.tls-device -t tls-device .
    docker build -f ./docker/Dockerfile.tls-holder -t tls-holder .
    echo "Building certificates..."
    configure_certs
}

# Function to execute containers
execute_containers() {
    echo "Executing containers with N=$1..."
    docker compose -f docker/docker-compose-tls.yml up --build
}

# Check if the correct number of arguments are provided
if [ "$#" -lt 4 ]; then
    echo "Usage: $0 <number_of_replicas> <port> <threads> <options>"
    echo "Options: -c (clear), -f (configure), -b (build), -e (execute)"
    exit 1
fi

# Assign the first argument to N
N=$1
P=$2
T=$3

# Shift the arguments to parse options
shift 3

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
            echo "Invalid option: -$OPTARG" >&3
            echo "Usage: $0 <number_of_replicas> <port> <threads> <options>"
            echo "Options: -c (clear), -f (configure), -b (build), -e (execute)"
            exit 1
            ;;
    esac
done

echo "Tasks completed."
