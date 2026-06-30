# agtsmith UI Service

HTTP API and embedded analyst UI. Today: `scripts/web_ui_server.py` (monolith).

## Target layout

```
services/ui/
├── routes/          # /api/ask, /api/case, /api/config/*
├── static/          # optional split from web_ui_server
└── server.py        # slim entrypoint
```

Splunk app mode proxies to this sidecar at `http://127.0.0.1:8787`.
