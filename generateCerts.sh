#!/bin/bash

# Check if an argument if provided
if [ -z "$1" ]; then
    echo "Usage: $0 <number_of_holders>"
    exit 1
fi

# Check if the provided argument if a positive integer
if ! [[ "$1" =~ ^[0-9]+$ ]] || [ "$1" -le 0 ]; then
  echo "Please provide a positive integer as input."
  exit 1
fi

# Remove old certs
rm certs/*

# Number of holders
N=$1

# Keystore password and key password
KEYSTORE_PASSWORD="password"
KEY_PASSWORD="password"

# Generate N keystores
for ((i = 1; i <= N; i++)); do
    DNAME="CN=holder_$i, OU=MyUnit, O=MyOrg, L=MyCity, ST=MyState, C=US"
    KEYSTORE_NAME="holder_$i.keystore"

    keytool -genkeypair \
            -alias holder$i \
            -keyalg EC \
            -groupname secp256r1 \
            -keystore "certs/$KEYSTORE_NAME" \
            -storepass "$KEYSTORE_PASSWORD" \
            -keypass "$KEY_PASSWORD" \
            -dname "$DNAME" \
            -validity 3650

    keytool -export \
            -alias holder$i \
            -keystore "certs/$KEYSTORE_NAME" \
            -storepass "$KEY_PASSWORD" \
            -file "certs/holder_$i.crt"

    keytool -import \
            -alias holder$i \
            -file "certs/holder_$i.crt" \
            -keystore certs/client.truststore \
            -storepass "$KEYSTORE_PASSWORD" \
            -noprompt
  
    if [ $? -eq 0 ]; then
        echo "Generated $KEYSTORE_NAME"
    else
        echo "Failed to generate $KEYSTORE_NAME"
    fi
done
