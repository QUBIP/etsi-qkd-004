# QKD Application Interface

This is a dockerized Python implementation of a server/client example of the [ETSI GS QKD 004 API Standard](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/004/02.01.01_60/gs_qkd004v020101p.pdf).

## Table of Contents

- [Prerequisites](#prerequisites)
- [Setup](#setup)
  - [Generate Certificates](#generate-certificates)
- [Running the Application](#running-the-application)
  - [Start the Server](#start-the-server)
  - [Generate the Key](#generate-the-key)
  - [Run the Client](#run-the-client)
  - [Stop the Server](#stop-the-server)
- [Testing](#testing)
  - [Running Tests](#running-tests)
  - [Test Results](#test-results)
- [Sample Logs](#sample-logs)
  - [Server Logs](#server-logs)
  - [Client Logs](#client-logs)

## Prerequisites

- [Docker]](https://docs.docker.com/get-started/get-docker/)

## Setup

### Generate Certificates

First, generate the self-signed certificates for the server:

```bash
sudo chmod +x ./certs/generate_certs.sh
./certs/generate_certs.sh qkd_server
```

## Running the Application

### Start the Server

Run the server in the background with:

```bash
docker compose up --build -d qkd_server
```

### Generate the Key

Run the simulated QKD key generation tool with:

```bash
docker compose run --build --rm generate_key
```

### Run the Client

Run the client with:

```bash
docker compose run --build --rm qkd_client
```

### Stop the Server

Stop the server running in the background with

```bash
docker compose down
```

## Testing

### Running Tests

To run the test suite using `pytest`, execute the following commands in the project directory:

```bash
./certs/generate_certs.sh localhost
docker-compose up --build -d qkd_server
docker compose run --build --rm generate_key
pytest tests.py
```

### Test Results

Below are the results from running the test suite:

```
=== test session starts ===
platform linux -- Python 3.10.12, pytest-8.3.4, pluggy-1.5.0
rootdir: etsi-qkd-004
collected 9 items                                                                                      
                                                                                             
test_client.py ......... [100%]
                                                                                             
=== 9 passed in 5.05s ===
```

All tests have passed successfully, indicating that the client interacts with the server as expected under various scenarios.

## Sample Logs

### Server Logs

After running the server and client, the server logs should appear as follows:

```
[INFO] Running server on localhost:25575
[DEBUG] Version 2.1.1. Received service type: 2
[DEBUG] Connection Info: {'peername': ('127.0.0.1', 57368), 'cipher': ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)}
[DEBUG] Source URI received by server: client://localhost
[DEBUG] Destination URI received by server: server://localhost
[DEBUG] QoS received by server: {'Key_chunk_size': 512, 'Max_bps': 40000, 'Min_bps': 5000, 'Jitter': 10, 'Priority': 0, 'Timeout': 5000, 'TTL': 3600, 'Metadata_mimetype': 'application/json'}
[INFO] OPEN_CONNECT successful for Key_stream_ID: 7d099bfd-e51f-4499-a866-a451e66170ae
[DEBUG] Version 2.1.1. Received service type: 4
[DEBUG] Key delivered by server: first 8 bytes 6c4adb10518d9edb, last 8 bytes 804fb1db688e9759
[INFO] GET_KEY successful for Key_stream_ID: 7d099bfd-e51f-4499-a866-a451e66170ae, Index: 0
[DEBUG] Version 2.1.1. Received service type: 8
[INFO] CLOSE successful for Key_stream_ID: 7d099bfd-e51f-4499-a866-a451e66170ae
```

### Client Logs

The client logs should appear as follows:

```
[INFO] Connected to server at localhost:25575
[DEBUG] Source URI sent by client: client://localhost
[DEBUG] Destination URI sent by client: server://localhost
[DEBUG] QoS sent by client: {'Key_chunk_size': 512, 'Max_bps': 40000, 'Min_bps': 5000, 'Jitter': 10, 'Priority': 0, 'Timeout': 5000, 'TTL': 3600, 'Metadata_mimetype': 'application/json'}
[DEBUG] Version 2.1.1. Received service type: 3
[DEBUG] QoS received by client: {'Key_chunk_size': 512, 'Max_bps': 40000, 'Min_bps': 5000, 'Jitter': 10, 'Priority': 0, 'Timeout': 5000, 'TTL': 3600, 'Metadata_mimetype': 'application/json'}
[INFO] OPEN_CONNECT status: 0, Key_stream_ID: 7d099bfd-e51f-4499-a866-a451e66170ae
[DEBUG] Metadata size requested by client: 1024
[DEBUG] Version 2.1.1. Received service type: 5
[DEBUG] Index received by client: 0
[DEBUG] Metadata size received by client: 33
[DEBUG] Key received by client: first 8 bytes 6c4adb10518d9edb, last 8 bytes 804fb1db688e9759
[DEBUG] Metadata received by client: {"age": 1733220943474, "hops": 0}
[INFO] GET_KEY status: 0, Key_stream_ID: 7d099bfd-e51f-4499-a866-a451e66170ae, Key length: 512, Metadata: {"age": 1733220943474, "hops": 0}
[DEBUG] Version 2.1.1. Received service type: 9
[INFO] CLOSE status: 0, Key_stream_ID: 7d099bfd-e51f-4499-a866-a451e66170ae
```

These logs demonstrate the successful execution of the client-server interactions, including establishing a connection, exchanging keys, and closing the connection.
