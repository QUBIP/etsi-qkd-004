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

- [Docker](https://docs.docker.com/get-started/get-docker/)

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
docker compose up --build -d generate_key
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
docker compose up --build -d qkd_server
docker compose up --build -d generate_key
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
[INFO] Running server on 0.0.0.0:25575
[DEBUG] Version 1.0.1. Received service type: 2
[DEBUG] Connection Info: {'peername': ('172.25.0.1', 40372), 'cipher': ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)}
[DEBUG] Source URI received by server: client://localhost
[DEBUG] Destination URI received by server: server://localhost
[DEBUG] QoS received by server: {'Key_chunk_size': 512, 'Max_bps': 40000, 'Min_bps': 5000, 'Jitter': 10, 'Priority': 0, 'Timeout': 5000, 'TTL': 3600, 'Metadata_mimetype': 'application/json'}
[INFO] OPEN_CONNECT successful for Key_stream_ID: 52942d50-5756-4193-a1d6-8b8035bc0cf4
[DEBUG] Version 1.0.1. Received service type: 4
[DEBUG] Key delivered by server: first 8 bytes 65430124a7da8fa9, last 8 bytes 3f92beeae1a57db4
[INFO] GET_KEY successful for Key_stream_ID: 52942d50-5756-4193-a1d6-8b8035bc0cf4, Index: 0
[DEBUG] Version 1.0.1. Received service type: 8
[INFO] CLOSE successful for Key_stream_ID: 52942d50-5756-4193-a1d6-8b8035bc0cf4
```

### Client Logs

The client logs should appear as follows:

```
[INFO] Connected to server at qkd_server:25575
[DEBUG] Source URI sent by client: client://localhost
[DEBUG] Destination URI sent by client: server://qkd_server
[DEBUG] QoS sent by client: {'Key_chunk_size': 32, 'Max_bps': 40000, 'Min_bps': 5000, 'Jitter': 10, 'Priority': 0, 'Timeout': 5000, 'TTL': 3600, 'Metadata_mimetype': 'application/json'}
[DEBUG] Version 1.0.1. Received service type: 3
[DEBUG] QoS received by client: {'Key_chunk_size': 32, 'Max_bps': 40000, 'Min_bps': 5000, 'Jitter': 10, 'Priority': 0, 'Timeout': 5000, 'TTL': 3600, 'Metadata_mimetype': 'application/json'}
[INFO] OPEN_CONNECT status: 0, Key_stream_ID: c0c68f18-fa8f-458b-a282-8c728ccea32e
[DEBUG] Metadata size requested by client: 1024
[DEBUG] Version 1.0.1. Received service type: 5
[DEBUG] Index received by client: 0
[DEBUG] Metadata size received by client: 33
[DEBUG] Key received by client: first 8 bytes 5ebb6bb0290204b3, last 8 bytes 66aba5e6f8526b51
[DEBUG] Metadata received by client: {"age": 1739786484389, "hops": 0}
[INFO] GET_KEY status: 0, Key_stream_ID: c0c68f18-fa8f-458b-a282-8c728ccea32e, Key length: 32, Metadata: {"age": 1739786484389, "hops": 0}
[DEBUG] Version 1.0.1. Received service type: 9
[INFO] CLOSE status: 0, Key_stream_ID: c0c68f18-fa8f-458b-a282-8c728ccea32e
```

These logs demonstrate the successful execution of the client-server interactions, including establishing a connection, exchanging keys, and closing the connection.
