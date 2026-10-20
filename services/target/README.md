# vulnbank — local scan target

⚠️ **Intentionally vulnerable. Local testing only. Never deploy.**

A tiny FastAPI app with deliberate flaws so aidetector has real findings to
catch. FastAPI serves its own spec at `/openapi.json`.

| Endpoint | Deliberate flaw | OWASP |
| --- | --- | --- |
| `GET /accounts/{id}` | any user reads any account | API1 BOLA |
| `GET /accounts/{id}` | any non-empty token accepted | API2 Auth |
| `POST /accounts/{id}/transfer` | no ownership check | API1 BOLA |
| `POST /admin/users/{id}/promote` | no role check | API5 BFLA |
| `GET /search?q=` | reflects input unescaped | XSS / INJ |

## Seed identities (two roles → BOLA/BFLA testable)

| username | token | role |
| --- | --- | --- |
| alice | `alice-token` | user |
| admin | `admin-token` | admin |

## Run standalone

```bash
cd services/target
pip install -r requirements.txt
uvicorn app.main:app --port 9000
# spec: http://localhost:9000/openapi.json
```

In the compose stack it runs as service `target` on port 9000.
