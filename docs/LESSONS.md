# Lessons learned building this pipeline

## 1. LLM request bodies must be built in code, not templated as strings

Both Shuffle's Http node and early attempts in n8n hit the same failure
mode: an LLM's raw text response (or a multi-line prompt) can contain
literal newlines and unescaped quotes. If the request body is built by
string concatenation/templating (`{{ }}` expressions, manual JSON
strings typed into a UI), these characters corrupt the JSON and the
target API returns a generic "failed parsing request body" error that
gives no indication of the real cause.

**Fix:** always build the request body as a real object/dict in a proper
code context (n8n Code node, Python dict, etc.) and let the language's
own JSON serializer (`JSON.stringify`, `json.dumps`) handle escaping.
Never hand-construct a JSON string with `+` concatenation or a templated
string containing user/LLM-provided text.

## 2. GLPI's `input` field is an object, not an array

`POST /apirest.php/Ticket` expects:
```json
{ "input": { "name": "...", "content": "..." } }
```
Sending `"input": [...]` produces `ERROR_BAD_ARRAY` with no further detail.

## 3. n8n blocks `$env` access by default

Expressions referencing `$env.SOME_VAR` fail with "access to env vars
denied" unless the container is started with
`N8N_BLOCK_ENV_ACCESS_IN_NODE=false`. This is an intentional n8n security
default, not a bug.

## 4. n8n's secure-cookie default breaks plain-HTTP internal deployments

Running n8n over plain HTTP (no TLS) on an internal LAN causes the setup
UI to refuse to load, citing a secure-cookie requirement. Set
`N8N_SECURE_COOKIE=false` for internal-only, non-TLS deployments.

## 5. GLPI session tokens must be closed

Every `initSession` call should be paired with a `killSession` call after
the work is done, to avoid leaking open sessions on the GLPI side.

## 6. Test environment resource sizing matters

A VM with < 3GB free RAM struggled to reliably run Docker + n8n alongside
other already-running VMs on the same host. Size new VMs with real
headroom, not the bare documented minimum, especially on hosts already
running multiple services.
