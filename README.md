To run the program execute this in Alice node:

```bash
docker compose -f docker-compose-alice.yml kill && \
docker compose -f docker-compose-alice.yml up -d --build --force-recreate && \
docker compose -f docker-compose-alice.yml logs -f qkd_server_alice
```

and this in Bob node:

```bash
docker compose -f docker-compose-bob.yml kill && \
docker compose -f docker-compose-bob.yml up -d --build --force-recreate && \
docker compose -f docker-compose-bob.yml logs -f qkd_server_bob
```