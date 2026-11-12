// The SQL of one append, in plain JavaScript, as a floor for the Rust Durable
// Object: 4 reads, then 3 inserts in one transactionSync.
import { DurableObject } from "cloudflare:workers";

export class Base extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec("CREATE TABLE IF NOT EXISTS nslog (seq INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, prev TEXT, entry TEXT NOT NULL, author TEXT NOT NULL, created INTEGER NOT NULL, gesture TEXT, undoes TEXT, config_seq INTEGER NOT NULL)");
    this.sql.exec("CREATE TABLE IF NOT EXISTS resources (name TEXT PRIMARY KEY, head INTEGER NOT NULL, live INTEGER)");
    this.sql.exec("CREATE TABLE IF NOT EXISTS entries (seq INTEGER PRIMARY KEY, resource TEXT NOT NULL, id TEXT NOT NULL, parent TEXT, kind INTEGER NOT NULL, patches TEXT, author TEXT NOT NULL, created INTEGER NOT NULL, gesture TEXT, undoes TEXT, ns_seq INTEGER NOT NULL, depth INTEGER NOT NULL)");
    this.sql.exec("CREATE UNIQUE INDEX IF NOT EXISTS entries_by_id ON entries(resource, id)");
    this.n = 0;
  }
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname.endsWith("/noop")) return new Response("{}");
    const body = await req.text();
    const i = ++this.n;
    const id = `1${i.toString(36).padStart(32, "a")}`;
    this.sql.exec("SELECT head, live FROM resources WHERE name = ?", "d").toArray();
    this.sql.exec("SELECT * FROM entries WHERE seq = ?", i - 1).toArray();
    this.sql.exec("SELECT * FROM entries WHERE resource = ? AND id = ?", "d", id).toArray();
    this.sql.exec("SELECT MAX(seq) AS m FROM entries").toArray();
    this.ctx.storage.transactionSync(() => {
      this.sql.exec("INSERT INTO nslog (seq, id, prev, entry, author, created, gesture, undoes, config_seq) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", i, id, null, '{"kind":"head"}', "a", Date.now(), null, null, 1);
      this.sql.exec("INSERT INTO entries (seq, resource, id, parent, kind, patches, author, created, gesture, undoes, ns_seq, depth) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?)", i, "d", id, null, body, "a", Date.now(), null, null, i, i);
      this.sql.exec("INSERT INTO resources (name, head, live) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET head = excluded.head, live = excluded.live", "d", i, i);
    });
    return new Response(null, { status: 201, headers: { ETag: `"${id}"`, "Cache-Control": "no-store" } });
  }
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === "/") return new Response("{}");
    return env.BASE.get(env.BASE.idFromName("one")).fetch(req);
  },
};
