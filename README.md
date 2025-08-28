To run the program execute this in Alice node:

```bash
docker compose kill && docker compose up -d --build && docker compose logs -f
```

To test the client edit `config/link_map.json`, `config/config.json` and `config/open_connect_request.json` and execute the client with:

```bash
python client.py
```