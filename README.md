# ElasticGateway

[![codecov](https://codecov.io/gh/define42/elasticgateway/graph/badge.svg?token=E2GZ1ZDEPS)](https://codecov.io/gh/define42/elasticgateway)
[![Go Report Card](https://goreportcard.com/badge/github.com/define42/elasticgateway)](https://goreportcard.com/report/github.com/define42/elasticgateway)
[![Build Status](https://github.com/define42/elasticgateway/actions/workflows/build.yml/badge.svg)](https://github.com/define42/elasticgateway/actions/)

ElasticGateway is a compliance-oriented namespace and ingest gateway for self-managed Elastic Stack Basic/free.
It turns LDAP group membership into Elasticsearch native users, Elastic roles, Kibana Spaces, Kibana data views, and namespace-scoped ingest permissions.


## Access Model

LDAP groups are the source of truth.
The gateway reads group names from `LDAP_GROUP_ATTRIBUTE`, keeps only groups matching `LDAP_GROUP_PREFIX`, and maps suffixes to permissions:

| LDAP group | Namespace | Kibana space privilege | Elasticsearch index pattern | Ingest |
| --- | --- | --- | --- | --- |
| `<namespace>_user` | `<namespace>` | full Discover, Dashboard, and Visualize access | read on `<namespace>-*` | no |
| `<namespace>_ingest` | `<namespace>` | full space access | read and write on `<namespace>-*` | yes |
| `<namespace>_admin` | `<namespace>` | full space access | read, write, and delete on `<namespace>-*` | yes |

User groups (`<namespace>_user`) get feature-level Kibana `all` privileges for `dashboard_v2`, `visualize_v2`, and `discover_v2`; they do not get Kibana `base` privileges, so Stack Management is not granted.
Write-capable groups (`<namespace>_ingest` and `<namespace>_admin`) get Kibana `base: ["all"]` inside their namespace space.

On login, the gateway provisions:

- Kibana space named exactly like the namespace, such as `team10`
- Kibana data view for the namespace or index family, such as `team10-*` or `team10-hello-*`
- Kibana security role named `gateway_<namespace>_<mode>`
- Elasticsearch native user for the login session, with a generated per-login password

Multiple groups mean multiple namespaces. Duplicate groups for one namespace collapse to the strongest permission.
If two namespaces could match one ingest path, the longest namespace wins.

## Ingest Model

Writes use one of:

```text
POST /ingest/<namespace>-<index>
POST /ingest/<namespace>-<index>/_bulk
```

The namespace prefix is the authorization boundary.
The gateway accepts an ingest request only when the authenticated user has write-capable LDAP access for the namespace at the front of the path.

Every document must contain a top-level UTC `event_time`.
That timestamp controls the daily rollover alias:

```text
<namespace>-<index>-YYYYMMDD-rollover
```

For:

```text
POST /ingest/team10-hello
event_time = 2024-12-30T10:11:12Z
```

the gateway creates or uses:

| Resource | Name |
| --- | --- |
| Kibana space | `team10` |
| Data view ID | `gateway-index-pattern-team10-hello` |
| Data view title | `team10-hello-*` |
| Write alias | `team10-hello-20241230-rollover` |
| First backing index | `team10-hello-20241230-rollover-000001` |

Single-document ingest accepts one `application/json` object.
Bulk ingest accepts Elasticsearch-style `application/x-ndjson` action/source pairs at `/_bulk`.
Supported bulk actions are `index` and `create`.
The gateway ignores any client-provided `_index` metadata and routes each source document to the write alias computed from that document's `event_time`; other metadata such as `_id` is forwarded.
One bulk request can therefore write to multiple daily rollover aliases, and the gateway ensures each required alias before forwarding the request to Elasticsearch's `_bulk` API.

## Elastic Resources

At startup, the gateway bootstraps shared Elasticsearch resources:

- ILM policy `generic-rollover-100m`
- index template `gateway-rollover-template`
- template index pattern `*-*-rollover-*`
- `event_time` mapping as an Elasticsearch `date`
- default template settings of `1` shard and `1` replica per rollover backing index

New backing indices are created with:

- alias `is_write_index: true`
- `index.lifecycle.name: generic-rollover-100m`
- `index.lifecycle.rollover_alias: <write-alias>`

For aliases that already exist, the gateway resolves the concrete write backing index and updates `/{index}/_settings` with the ILM policy and rollover alias.

## HTTP API

`GET /` redirects to `/login`.

`GET /login` renders the login page. If the request already has a valid session cookie, it redirects to `/kibana/s/<first_namespace>/app/home`, or `/kibana/app/home` when the session has no namespace access.

`POST /login` authenticates against LDAP, provisions Elasticsearch and Kibana resources, sets the session cookie, and redirects to the first namespace space in Kibana.

`POST /logout` clears the session cookie and forgets cached ingest credentials for the logged-in user. Kibana logout requests under `/kibana/auth/logout`, `/kibana/logout`, `/kibana/api/security/logout`, and `/kibana/security/logout` are handled the same way.

`/kibana` and `/kibana/*` reverse proxy Kibana. A valid gateway session is required.

`GET /demo` serves a browser form for sending test ingest requests.

`POST /ingest/<namespace>-<index>` writes one JSON document to Elasticsearch. Authentication can be HTTP Basic auth with LDAP credentials or a gateway session cookie.

`POST /ingest/<namespace>-<index>/_bulk` writes Elasticsearch-style NDJSON action/source pairs to Elasticsearch through the bulk API. Each source document must include `event_time`, and each source document is routed independently to its daily rollover alias.

## Configuration

Configuration is environment based.

| Variable | Default | Description |
| --- | --- | --- |
| `LISTEN_ADDR` | `:8080` | Gateway bind address |
| `ELASTICSEARCH_URL` | `https://localhost:9200` | Elasticsearch API URL |
| `ELASTICSEARCH_USERNAME` | `elastic` | Elasticsearch admin/API username |
| `ELASTICSEARCH_PASSWORD` | `ELASTIC_PASSWORD` or empty | Elasticsearch admin/API password |
| `ELASTICSEARCH_SKIP_TLS_VERIFY` | `false` | Disable Elasticsearch TLS verification |
| `KIBANA_URL` | `http://localhost:5601` | Kibana API URL |
| `KIBANA_USERNAME` | `ELASTICSEARCH_USERNAME` or `elastic` | Kibana API username |
| `KIBANA_PASSWORD` | `ELASTICSEARCH_PASSWORD` or `ELASTIC_PASSWORD` or empty | Kibana API password |
| `SESSION_SECRET` | generated at process start | Shared secret used to sign and encrypt gateway session cookies |
| `FORCE_SECURE_COOKIES` | `false` | Always set the session cookie `Secure` flag and send `X-Forwarded-Proto: https` to Kibana, for TLS-terminating load balancers |
| `LDAP_URL` | `ldaps://ldap:389` | LDAP server URL |
| `LDAP_BASE_DN` | `dc=glauth,dc=com` | LDAP search base |
| `LDAP_USER_FILTER` | `(mail=%s)` | User lookup filter; `%s` receives the login email |
| `LDAP_GROUP_ATTRIBUTE` | `memberOf` | Attribute containing group memberships |
| `LDAP_GROUP_PREFIX` | `team` | Prefix required for gateway-managed groups |
| `LDAP_USER_DOMAIN` | `@example.com` | Domain appended to usernames without `@` before LDAP bind/search |
| `LDAP_STARTTLS` | `false` | Start TLS after connecting to `ldap://` URLs |
| `LDAP_SKIP_TLS_VERIFY` | `true` | Disable LDAP TLS verification |

Production notes:

- Set `LDAP_SKIP_TLS_VERIFY=false` with trusted LDAP certificates.
- Set `ELASTICSEARCH_SKIP_TLS_VERIFY=false` outside local self-signed development.
- Run the gateway behind HTTPS. If TLS terminates before the gateway, set `FORCE_SECURE_COOKIES=true` so session cookies are still sent with the `Secure` flag.
- Set the same long random `SESSION_SECRET` on every gateway instance so sessions survive restarts and load-balanced requests.
- If `SESSION_SECRET` is unset, the gateway generates random per-process session keys and restart invalidates existing sessions.
- The gateway API user needs permission to manage ILM policies, index templates, spaces, roles, native users, data views, and indices.

## Local Docker Demo

The repository includes a Compose stack for Elasticsearch 9.3.4, Kibana 9.3.4, the gateway, and GLAuth:

```bash
docker compose up --build
```

The local stack exposes:

| Service | URL |
| --- | --- |
| Gateway | `http://localhost:8080` |
| Elasticsearch | `http://localhost:9200` |
| Kibana direct service/API | `http://localhost:5601` |
| Kibana through the gateway | `http://localhost:8080/kibana` |
| GLAuth LDAP | `ldaps://localhost:1389` |

The gateway owns the public `/kibana` prefix and strips it before forwarding requests to Kibana.

Default local passwords:

| Account | Password |
| --- | --- |
| `elastic` | `Cedar7!FluxOrbit29` |
| `kibana_system` | `Kibana7!FluxOrbit29` |

Override them before starting the stack:

```bash
export ELASTIC_VERSION=9.3.4
export ELASTIC_PASSWORD='your-strong-password'
export KIBANA_SYSTEM_PASSWORD='another-strong-password'
docker compose up --build
```

The bundled LDAP fixture includes users that demonstrate permission suffixes:

| Username | Password | Groups | Result |
| --- | --- | --- | --- |
| `testuser` | `dogood` | `team1_admin`, `team2_ingest`, `team10_user` | multiple spaces with mixed permissions |
| `ingestuser` | `dogood` | `team10_ingest` | can write to `team10-*` ingest targets |
| `johndoe` | `dogood` | `team10_user` | can use Discover, Dashboard, and Visualize for `team10`, cannot ingest |

Example write:

```bash
curl -i http://localhost:8080/ingest/team10-hello \
  -u ingestuser:dogood \
  -H 'Content-Type: application/json' \
  -d '{
    "event_time": "2024-12-30T10:11:12Z",
    "message": "hello from the gateway",
    "customer_id": 42
  }'
```

Example bulk write:

```bash
curl -i http://localhost:8080/ingest/team10-hello/_bulk \
  -u ingestuser:dogood \
  -H 'Content-Type: application/x-ndjson' \
  --data-binary @- <<'NDJSON'
{"index":{"_id":"hello-1"}}
{"event_time":"2024-12-30T10:11:12Z","message":"hello from bulk"}
{"create":{"_id":"hello-3"}}
{"event_time":"2024-12-31T00:00:00Z","message":"another rollover day"}
{ "index": {} }
{ "event_time": "2026-05-09T12:00:00Z", "sku": "A-002", "name": "Nut", "price": 0.49 }
NDJSON
```

## Running Without Docker

```bash
export ELASTICSEARCH_URL=http://localhost:9200
export ELASTICSEARCH_USERNAME=elastic
export ELASTICSEARCH_PASSWORD='Cedar7!FluxOrbit29'
export KIBANA_URL=http://localhost:5601
export KIBANA_USERNAME=elastic
export KIBANA_PASSWORD='Cedar7!FluxOrbit29'
export LDAP_URL=ldaps://localhost:1389
export LISTEN_ADDR=:8080

go run .
```

## Development

Useful commands:

```bash
go test ./...
go test ./... -short
```

The LDAP integration tests use Docker for GLAuth and skip automatically when Docker is unavailable. Use `go test ./... -short` to skip Docker-backed tests explicitly.

Repository layout:

| Path | Purpose |
| --- | --- |
| `main.go` | startup, shared Elasticsearch bootstrap, HTTP server lifecycle |
| `internal/config` | environment-backed runtime config |
| `internal/ldap` | LDAP bind/search and group-to-access mapping |
| `internal/authz` | namespace authorization semantics |
| `internal/ingest` | ingest path parsing, document validation, auth cache |
| `internal/elastic` | Elasticsearch, Elastic security, ILM, Kibana Spaces, and data-view clients |
| `internal/server` | HTTP routes, login flow, sessions, Kibana proxy |
| `internal/server/templates` | embedded login and demo pages |
| `docker-compose.yml` | local Elastic Stack, gateway, and LDAP stack |
| `testldap/default-config.cfg` | local LDAP users and groups |

## Limitations

- Shard and replica counts are currently hard-coded in the gateway config.
- Kibana resource setup is synchronous; failed space or data-view creation fails the ingest before writing the document.
- The service is built for namespace-prefixed index families, not arbitrary Elasticsearch indexing.
