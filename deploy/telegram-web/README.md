## Telegram Web tailnet stack

This is the deployment-only Compose project for the Telegram Web K static
artifact. It is intentionally separate from the development Compose file at
the repository root and from `/opt/telegram-server`. Its explicit
`telegram-web-edge` project, `telegram-web-edge-net` network, and
`telegram-web-edge-nginx-cache` volume names keep a root-directory Compose
invocation from selecting this stack by basename.

The target checkout is `/opt/telegram-web`. Run the commands below from this
directory:

```sh
cd /opt/telegram-web/deploy/telegram-web
docker compose up -d --build
docker compose ps
```

The SPA is available at `http://100.124.236.66:8080/` from the tailnet. The
host-side port is explicitly bound to `tailscale0`; it must not be changed to
`0.0.0.0` or published through Funnel.

The image copies the committed `public/` artifact directly. It does not run a
Node or Vite build on the LXC. Resource isolation is provided by the target
LXC's existing 2 vCPU and 4 GiB allocation, leaving the box's CPU and memory
for Postgres and `telegramd`; the nested Docker cgroup exposes no controllers,
so this Compose service deliberately requests no per-container memory, CPU, or
PID limit. Nginx logs go to the container log with Docker's 10 MiB, three-file
rotation.

The enforced CSP allows `connect-src 'self'` only. The current Web K artifact
therefore cannot open its hard-coded official Telegram WebSocket or HTTP
endpoints: the browser reports a CSP violation and the client remains a
placeholder until a local endpoint is deliberately configured in a later
client/server change.

The only persistent volume is `telegram-web-edge-nginx-cache`, owned by this Compose
project. `docker compose down` is safe and leaves that cache intact; never use
`docker compose down -v` on this host.

Rollback is the code revert followed by `docker compose up -d --build` from this
directory. Verify success with `docker compose ps`, `curl -fsS http://100.124.236.66:8080/healthz`,
and a tailnet browser loading the SPA shell.
