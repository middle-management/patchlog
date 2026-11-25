# A JavaScript Durable Object doing an append's SQL, for comparison:
#   workerd serve bench/baseline/workerd.capnp --directory-path disk=/tmp/plb
using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [(name = "main", worker = .w), (name = "disk", disk = (path = "/tmp/plb", writable = true))],
  sockets = [(name = "http", address = "127.0.0.1:8789", http = (), service = "main")],
);
const w :Workerd.Worker = (
  modules = [(name = "worker.js", esModule = embed "worker.js")],
  compatibilityDate = "2025-10-01",
  bindings = [(name = "BASE", durableObjectNamespace = "Base")],
  durableObjectNamespaces = [(className = "Base", uniqueKey = "baseline", enableSql = true)],
  durableObjectStorage = (localDisk = "disk"),
);
