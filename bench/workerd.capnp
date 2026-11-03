# Runs the built Worker on plain workerd, without wrangler's dev proxy, for
# measurements:
#   npm run build && mkdir -p /tmp/pl && \
#   node_modules/.bin/workerd serve bench/workerd.capnp --directory-path disk=/tmp/pl
# Durable Object storage is SQLite on local disk; there is no Cache API
# service, so every read reaches the Durable Object.
using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [
    (name = "main", worker = .patchlog),
    (name = "disk", disk = (path = "/tmp/pl", writable = true)),
  ],
  sockets = [(name = "http", address = "127.0.0.1:8788", http = (), service = "main")],
);

const patchlog :Workerd.Worker = (
  modules = [
    (name = "index.js", esModule = embed "../crates/worker/build/index.js"),
    (name = "index_bg.wasm", wasm = embed "../crates/worker/build/index_bg.wasm"),
  ],
  compatibilityDate = "2025-10-01",
  bindings = [
    (name = "NAMESPACE", durableObjectNamespace = "Namespace"),
    (name = "ORIGIN", text = "http://127.0.0.1:8788"),
  ],
  durableObjectNamespaces = [(className = "Namespace", uniqueKey = "patchlog-namespace", enableSql = true)],
  durableObjectStorage = (localDisk = "disk"),
);
