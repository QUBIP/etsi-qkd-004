# QKD System Setup Guide

## Prerequisites

1. **Connect to Telefonica VPN**

## Simulated System Setup

### Option 1: Complete Stack on PAHM

1. SSH into hoke/ebano/trym
2. Navigate to `/home/mw/PAHM/ProxyAgentHybridModule`
3. Execute the complete stack following UPM instructions

### Option 2: QKD Simulator for Testing Only

1. SSH into hoke/ebano/trym
2. Navigate to `/home/mw/etsi-qkd-004` or clone this repository to another path
3. Start the Docker stack:
   ```bash
   docker compose up -d --build
   ```
4. View logs for the ETSI 004 server and key simulator:
   ```bash
   docker compose logs -f
   ```
5. To test the client:
   - Edit the configuration files:
     - `config/link_map.json`
     - `config/config.json`
     - `config/open_connect_request.json`
   - Define the request nodes
   - Run the client:
     ```bash
     python client.py
     ```

## Real System Setup

### 1. Power On Equipment

1. Turn on the electrical power from the PDU at https://192.168.159.66
2. Navigate to: **Control → RPDU → Outlet → Control Action on Immediate**
3. Select **Outlet 1 & Outlet 2** → **Next**

### 2. Launch Jupyter Notebooks

1. Access the Jupyter notebooks:
   - Alice: http://192.168.159.67:9090
   - Bob: http://192.168.159.68:9090
2. Open the respective notebooks:
   - Alice: `cv-qkd/notebooks/alice.ipynb`
   - Bob: `cv-qkd/notebooks/bob.ipynb`
3. Execute all cells in both notebooks: **Cell → Run All**

### 3. Start Docker Services

1. SSH into `qkd_alice` and `qkd_bob`
2. Navigate to `/home/xilinx/etsi-qkd-004`
3. On Alice, monitor the service logs (should start automatically):
   ```bash
   docker compose -f docker-compose-alice.yml logs -f
   ```
4. On Bob, start and monitor the service:
   ```bash
   docker compose -f docker-compose-bob.yml logs -f
   ```

### 4. Test the 004 Client

Run the client on both Alice and Bob:
```bash
python client.py
```

**Important:** The client must be executed simultaneously on both nodes to keep the buffer synchronized.

## Notes

- The buffer will contain all zeros until QKD keys are generated
- Key generation typically takes several minutes after running all notebook cells
- You can monitor the notebook logs to see when keys have been added to the buffer