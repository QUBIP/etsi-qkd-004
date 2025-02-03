#!/bin/bash

# Ensure the certs directory exists
mkdir -p certs

# Default CN is "localhost" if not provided
CN=${1:-localhost}

# Generate server certificates with the provided CN
openssl req -x509 -newkey rsa:4096 -keyout certs/server_key.pem -out certs/server_cert.pem -days 365 -nodes -subj "/CN=$CN"

# Generate client certificates with CN=qkd_client
openssl req -x509 -newkey rsa:4096 -keyout certs/client_key.pem -out certs/client_cert.pem -days 365 -nodes -subj "/CN=qkd_client"

# Set permissions
chmod 644 certs/*.pem
