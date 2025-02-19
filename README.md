# QKD Application Interface

This is a Dockerized Python implementation of a server/client example of the [ETSI GS QKD 004 API Standard](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/004/02.01.01_60/gs_qkd004v020101p.pdf), based on the [C implementation](https://forge.etsi.org/rep/qkd/gs004-app-int) from ETSI. It includes an emulation of a QKD link that distills synchronized keys at a fixed Secret Key Rate.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Setup](#setup)
  - [Generate Certificates](#generate-certificates)
- [Running the Application](#running-the-application)
  - [Run the Servers](#run-the-servers)
  - [Run the Clients](#run-the-clients)
  - [Run the Tests](#run-the-tests)
  - [Stop the Servers](#stop-the-servers)
- [Sample Logs](#sample-logs)
  - [Server Logs](#server-logs)
  - [Client Logs](#client-logs)
  - [Tests Results](#tests-results)

## Prerequisites

- [Docker](https://docs.docker.com/get-started/get-docker/)
- [OpenSSL](https://www.openssl.org/)

## Setup

### Generate Certificates

First, generate the self-signed certificates for the servers:

```bash
sudo chmod +x ./certs/generate_certs.sh
./certs/generate_certs.sh qkd_server_alice
./certs/generate_certs.sh qkd_server_bob
```

## Configuration

This application uses environment variables located at `docker-compose.yml` file for configuration. All variables are described inside the file.

## Running the Application

### Run the Servers

Run the API servers and the key generation emulators in the background:

```bash
docker compose up --build -d qkd_server_alice qkd_server_bob generate_key_alice generate_key_bob
```

### Run the Clients

Run the clients:

```bash
docker compose run --build --rm qkd_client_alice
docker compose run --build --rm qkd_client_bob
```

### Run the Tests

To run the test suite using `pytest`, execute:

```bash
docker compose run --build --rm qkd_tests_alice
docker compose run --build --rm qkd_tests_bob
```

### Stop the Servers

Stop and remove all running containers:

```bash
docker compose down
```

## Sample Logs

### Server Logs

After running the server and client, the server logs might appear as follows:

```
[INFO] Running server on 0.0.0.0:25575
[DEBUG] Version 1.0.1. Received service type: 2
[DEBUG] Connection Info: {'peername': ('172.25.0.6', 37438), 'cipher': ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)}
[DEBUG] Source URI received by server: client://localhost
[DEBUG] Destination URI received by server: server://qkd_server_alice
[DEBUG] QoS received by server: {'Key_chunk_size': 32, 'Max_bps': 40000, 'Min_bps': 5000, 'Jitter': 10, 'Priority': 0, 'Timeout': 5000, 'TTL': 3600, 'Metadata_mimetype': 'application/json'}
[INFO] OPEN_CONNECT successful for Key_stream_ID: c42fe0b3-dfa7-4872-b170-9d3b63b1f841
[DEBUG] Version 1.0.1. Received service type: 4
[DEBUG] Key delivered by server: first 8 bytes cf677843efe31c95, last 8 bytes 65d50308ea60bd62
[INFO] GET_KEY successful for Key_stream_ID: c42fe0b3-dfa7-4872-b170-9d3b63b1f841, Index: 0
[DEBUG] Version 1.0.1. Received service type: 8
[INFO] CLOSE successful for Key_stream_ID: c42fe0b3-dfa7-4872-b170-9d3b63b1f841
```

### Client Logs

The client logs might look like this:

```
[INFO] Connected to server at qkd_server_alice:25575
[DEBUG] Source URI sent by client: client://localhost
[DEBUG] Destination URI sent by client: server://qkd_server_alice
[DEBUG] QoS sent by client: {'Key_chunk_size': 32, 'Max_bps': 40000, 'Min_bps': 5000, 'Jitter': 10, 'Priority': 0, 'Timeout': 5000, 'TTL': 3600, 'Metadata_mimetype': 'application/json'}
[DEBUG] Version 1.0.1. Received service type: 3
[DEBUG] QoS received by client: {'Key_chunk_size': 32, 'Max_bps': 40000, 'Min_bps': 5000, 'Jitter': 10, 'Priority': 0, 'Timeout': 5000, 'TTL': 3600, 'Metadata_mimetype': 'application/json'}
[INFO] OPEN_CONNECT status: 0, Key_stream_ID: c42fe0b3-dfa7-4872-b170-9d3b63b1f841
[DEBUG] Metadata size requested by client: 1024
[DEBUG] Version 1.0.1. Received service type: 5
[DEBUG] Index received by client: 0
[DEBUG] Metadata size received by client: 33
[DEBUG] Key received by client: first 8 bytes cf677843efe31c95, last 8 bytes 65d50308ea60bd62
[DEBUG] Metadata received by client: {"age": 1739795939745, "hops": 0}
[INFO] GET_KEY status: 0, Key_stream_ID: c42fe0b3-dfa7-4872-b170-9d3b63b1f841, Key length: 32, Metadata: {"age": 1739795939745, "hops": 0}
[DEBUG] Version 1.0.1. Received service type: 9
[INFO] CLOSE status: 0, Key_stream_ID: c42fe0b3-dfa7-4872-b170-9d3b63b1f841
```

These logs demonstrate the successful execution of the client-server interactions, including establishing a connection, exchanging keys, and closing the connection.

### Tests Results

Below is an example of the test suite output:

```
====================== test session starts ======================
platform linux -- Python 3.9.21, pytest-8.3.4, pluggy-1.5.0
rootdir: /app
collected 9 items                                               

tests.py .........                                        [100%]

======================= 9 passed in 0.38s =======================
```

All tests have passed successfully, indicating that the client interacts with the server as expected under various scenarios, handling exceptions as required by the API standard.

## Contributing

Contributions are welcome. Please submit an issue or pull request if you'd like to contribute.

## Support

If you have any questions, please open an issue on this repository.

## License

This project is based on the [ETSI C implementation](https://forge.etsi.org/rep/qkd/gs004-app-int) and follows the same licensing terms.  

The source code is licensed under the **BSD 3-Clause License**. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

This work has been developed within the QUBIP project (https://www.qubip.eu),
funded by the European Union under the Horizon Europe framework programme
[grant agreement no. 101119746](https://doi.org/10.3030/101119746).