// Monthly cost of scenarios on Workers Paid, from the unit costs measured on
// Cloudflare (bench/RESULTS.md) and Cloudflare's published prices.
//   node bench/cost.mjs            prints a table per scenario
//   node bench/cost.mjs --json     the same as JSON

// Prices (Workers Paid, Standard), checked 2026-11-03:
// developers.cloudflare.com/workers/platform/pricing and /durable-objects/platform/pricing
const PRICE = {
  base: 5, // per account and month
  workerRequests: { included: 10e6, perMillion: 0.3 },
  workerCpuMs: { included: 30e6, perMillion: 0.02 },
  doRequests: { included: 1e6, perMillion: 0.15 },
  doGbSeconds: { included: 400e3, perMillion: 12.5 },
  rowsRead: { included: 25e9, perMillion: 0.001 },
  rowsWritten: { included: 50e6, perMillion: 1.0 },
  storageGbMonth: { included: 5, perUnit: 0.2 },
};

// Measured on Cloudflare unless marked.
const UNIT = {
  workerCpuMs: 1.0, // front Worker CPU per request, p50 0.9–1.0 ms
  rowsWrittenPerWrite: 4, // ns_log and res_log rows and their id indexes (workerd's rowsWritten); 6.0–7.7 before
  rowsReadPerWrite: 4,
  rowsReadPerRead: 2, // head reads come from memory; a revision read folds up to 16 entries
  activeMsPerWriteSparse: 20, // an object woken for one write stays active through its commit
  activeMsPerWriteBusy: 2.5, // under load, requests overlap
  activeMsPerRead: 3,
  bytesPerWrite: 512, // local SQLite, 0.5 KiB documents, snapshots every 16 entries
  pollIntervalS: 20, // §7.7's default interval
  objectGb: 0.128, // duration is billed at 128 MB per object: 7.66 GB-s per active minute measured
  // Long-poll as built: the wait is held in the front Worker, on a hibernatable
  // WebSocket to the object. Measured with 100 idle followers: 600 object
  // invocations a minute for 300 polls (the socket's connect and its close
  // event; a close may be billed as an incoming WebSocket message, at 1/20,
  // but is counted here as a request) and 0.35 s of activity a minute.
  doRequestsPerPoll: 2,
  activeMsPerPoll: 1.2,
  // Past this many waiters on a namespace, further polls wait in the object,
  // which then stays awake (HIBERNATING_WAITERS_MAX in ns.rs).
  hibernatingWaitersMax: 200,
  bytesPerPoll: 500, // a 204 with its headers, as served
  bytesPerRead: 2_000, // a small document with its headers, for reads a CDN serves
  // Verifying a grant in the namespace's object (bench/grant-overhead.mjs:
  // +0.34–0.53 ms of CPU a request on workerd), counted as active time.
  grantMsPerRequest: 0.45,
};

const SECONDS_PER_MONTH = 30 * 24 * 3600;

function usage(s) {
  const busy = s.busy ?? false;
  const followerPolls = (s.followers ?? 0) * (SECONDS_PER_MONTH / UNIT.pollIntervalS);
  // Each write answers every waiting follower of its namespace, which polls again.
  const wakePolls = (s.followers ?? 0) * (s.writesToFollowedNs ?? 0);
  const polls = followerPolls + wakePolls;
  // Behind Workers Cache, the followers of a namespace collapse into about one
  // miss per interval and per write (measured: 100 followers, 1 miss).
  const misses = (s.followedNamespaces ?? 0) * (SECONDS_PER_MONTH / UNIT.pollIntervalS + (s.writesToFollowedNs ?? 0));
  // Private namespaces (s.private) are read with grants: their responses are
  // no-store at every CDN (§9, no verifying edge), so nothing collapses or
  // is cached, and a CDN in front only relays.
  const priv = s.private ?? false;
  // Behind another CDN (s.cdn), only its misses reach Cloudflare at all.
  const collapsed = !priv && (s.workersCache || s.cdn);
  const pollsAtObject = s.collapsePolls ? 0 : collapsed ? misses : polls;
  // Followers per followed namespace decide where polls wait.
  const perNs = collapsed ? 1 : (s.followers ?? 0) / Math.max(1, s.followedNamespaces ?? 1);
  const hibernatingShare = s.waitsInObject ? 0 : Math.min(1, UNIT.hibernatingWaitersMax / Math.max(1, perNs));
  const awakeNamespaces = s.waitsInObject || perNs > UNIT.hibernatingWaitersMax ? (s.followedNamespaces ?? 0) : 0;
  const pollsAtWorker = s.pollsBypassWorker ? 0 : collapsed && s.cdn ? misses : polls;
  const cachedShare = priv ? 0 : (s.cachedShare ?? 0);
  const doReads = s.reads * (1 - cachedShare);
  // Behind another CDN, the cached reads are its, not the Worker's.
  const cdnReads = s.cdn ? s.reads * cachedShare : 0;
  const grantMs = priv || s.grants ? UNIT.grantMsPerRequest : 0;
  return {
    workerRequests: s.writes + s.reads - cdnReads + pollsAtWorker,
    // Cache hits are billed as Worker requests, but run no code.
    workerCpuMs: (s.writes + s.reads + (s.workersCache && !priv ? misses : pollsAtWorker)) * UNIT.workerCpuMs,
    doRequests:
      s.writes + doReads + pollsAtObject * (1 + hibernatingShare * (UNIT.doRequestsPerPoll - 1)),
    doGbSeconds:
      UNIT.objectGb *
      ((s.writes * (busy ? UNIT.activeMsPerWriteBusy : UNIT.activeMsPerWriteSparse) + doReads * UNIT.activeMsPerRead) / 1000 +
        // Waits held inside an object keep it active all month (measured: 59.8 s of every minute).
        awakeNamespaces * SECONDS_PER_MONTH +
        (awakeNamespaces ? 0 : (pollsAtObject * UNIT.activeMsPerPoll) / 1000) +
        ((s.writes + doReads + pollsAtObject) * grantMs) / 1000),
    rowsRead: s.writes * UNIT.rowsReadPerWrite + doReads * UNIT.rowsReadPerRead,
    rowsWritten: s.writes * (s.rowsWrittenPerWrite ?? UNIT.rowsWrittenPerWrite),
    storageGbMonth: s.storedGb ?? 0,
    // A CDN in front of private namespaces relays every read as well.
    cdnRequests: s.cdn ? polls + (priv ? s.reads : cdnReads) : 0,
    cdnGb: s.cdn ? (polls * UNIT.bytesPerPoll + (priv ? s.reads : cdnReads) * UNIT.bytesPerRead) / 1e9 : 0,
    cdn: s.cdn,
  };
}

function cost(u) {
  const over = (n, p) => (Math.max(0, n - p.included) / 1e6) * p.perMillion;
  const lines = {
    "Workers Paid base": PRICE.base,
    "Worker requests": over(u.workerRequests, PRICE.workerRequests),
    "Worker CPU": over(u.workerCpuMs, PRICE.workerCpuMs),
    "DO requests": over(u.doRequests, PRICE.doRequests),
    "DO duration": over(u.doGbSeconds, PRICE.doGbSeconds),
    "SQLite rows read": over(u.rowsRead, PRICE.rowsRead),
    "SQLite rows written": over(u.rowsWritten, PRICE.rowsWritten),
    "SQLite storage": Math.max(0, u.storageGbMonth - PRICE.storageGbMonth.included) * PRICE.storageGbMonth.perUnit,
    ...(u.cdn
      ? {
          [`${u.cdn.name} requests`]: (u.cdnRequests / 1e6) * u.cdn.perMillion,
          [`${u.cdn.name} bandwidth`]: u.cdnGb * u.cdn.perGb,
        }
      : {}),
  };
  return { lines, total: Object.values(lines).reduce((a, b) => a + b, 0) };
}

const M = 1e6;
const SCENARIOS = [
  {
    name: "Small team CMS",
    about: "50 namespaces; 10,000 saves a day; 100,000 API reads a day, half from the Cache API; 2 GB stored",
    writes: 0.3 * M, reads: 3 * M, cachedShare: 0.5, storedGb: 2,
  },
  {
    name: "Collaborative SaaS",
    about: "5,000 namespaces; 1M saves a day; 10M reads a day, half cached; 2,000 open documents with 5 long-poll followers each; 50 GB stored",
    writes: 30 * M, reads: 300 * M, cachedShare: 0.5, storedGb: 50,
    followers: 10_000, followedNamespaces: 2_000, writesToFollowedNs: 30 * M / 2_000 / 2,
  },
  {
    name: "Collaborative SaaS, waits inside the object (as first built)",
    about: "The same, with long-polls waiting inside the namespace's object, as first built: an object with a waiting follower is billed all month",
    writes: 30 * M, reads: 300 * M, cachedShare: 0.5, storedGb: 50,
    followers: 10_000, followedNamespaces: 2_000, writesToFollowedNs: 30 * M / 2_000 / 2, waitsInObject: true,
  },
  {
    name: "Collaborative SaaS behind Bunny",
    about: "The collaborative scenario with Bunny in front: a document's followers share one miss per interval, cached reads are Bunny's (bandwidth only)",
    writes: 30 * M, reads: 300 * M, cachedShare: 0.5, storedGb: 50,
    followers: 10_000, followedNamespaces: 2_000, writesToFollowedNs: 30 * M / 2_000 / 2,
    cdn: { name: "Bunny", perMillion: 0, perGb: 0.01 },
  },
  {
    name: "Collaborative SaaS behind Fastly",
    about: "The same with Fastly in front, at about $0.75 per million requests and $0.12/GB (third-party figures, unconfirmed)",
    writes: 30 * M, reads: 300 * M, cachedShare: 0.5, storedGb: 50,
    followers: 10_000, followedNamespaces: 2_000, writesToFollowedNs: 30 * M / 2_000 / 2,
    cdn: { name: "Fastly", perMillion: 0.75, perGb: 0.12 },
  },
  {
    name: "Collaborative SaaS with grants, public namespaces",
    about: "The collaborative scenario behind Bunny, with every write made under a grant: public reads ignore grants, so only writes pay for verification",
    writes: 30 * M, reads: 300 * M, cachedShare: 0.5, storedGb: 50,
    followers: 10_000, followedNamespaces: 2_000, writesToFollowedNs: 30 * M / 2_000 / 2,
    cdn: { name: "Bunny", perMillion: 0, perGb: 0.01 }, grants: true,
  },
  {
    name: "Collaborative SaaS, private namespaces",
    about: "The collaborative scenario with every namespace read with grants: no CDN can cache a response, so every read and every follower's poll reaches the Worker and the object",
    writes: 30 * M, reads: 300 * M, cachedShare: 0.5, storedGb: 50,
    followers: 10_000, followedNamespaces: 2_000, writesToFollowedNs: 30 * M / 2_000 / 2, private: true,
  },
  {
    name: "Collaborative SaaS, private namespaces, behind Bunny",
    about: "The same behind Bunny, which relays everything and bills its bandwidth",
    writes: 30 * M, reads: 300 * M, cachedShare: 0.5, storedGb: 50,
    followers: 10_000, followedNamespaces: 2_000, writesToFollowedNs: 30 * M / 2_000 / 2, private: true,
    cdn: { name: "Bunny", perMillion: 0, perGb: 0.01 },
  },
  {
    name: "Device fleet, long-poll through the Worker, all waits inside the object (as first built)",
    about: "The same fleet as below, as first built",
    writes: 3_000, reads: 0, storedGb: 0.1,
    followers: 100_000, followedNamespaces: 10, writesToFollowedNs: 3_000 / 10, waitsInObject: true,
  },
  {
    name: "Device fleet, long-poll through the Worker",
    about: "100,000 devices each long-polling one of 10 public namespaces; 100 writes a day; polls answered by the Worker and the object (200 waiters a namespace hibernating, the rest waiting in the object)",
    writes: 3_000, reads: 0, storedGb: 0.1,
    followers: 100_000, followedNamespaces: 10, writesToFollowedNs: 3_000 / 10,
  },
  {
    name: "Device fleet behind Workers Cache",
    about: "The same fleet, with Workers Cache on (wrangler.toml [cache]): every poll is still a billed Worker request, but hits run nothing, and each namespace's followers collapse into one miss per interval",
    writes: 3_000, reads: 0, storedGb: 0.1,
    followers: 100_000, followedNamespaces: 10, writesToFollowedNs: 3_000 / 10, workersCache: true,
  },
  {
    name: "Collaborative SaaS behind Workers Cache",
    about: "The collaborative scenario with Workers Cache on: a document's 5 followers share one miss; reads hit the cache as before",
    writes: 30 * M, reads: 300 * M, cachedShare: 0.5, storedGb: 50,
    followers: 10_000, followedNamespaces: 2_000, writesToFollowedNs: 30 * M / 2_000 / 2, workersCache: true,
  },
  {
    name: "Device fleet behind Fastly",
    about: "The same fleet with a Fastly service in front of the Worker that caches the long-poll 204 (measured: 15 of 707 idle polls reached Cloudflare); Fastly at about $0.0075 per 10,000 requests and $0.12/GB in North America and Europe (third-party figures, unconfirmed)",
    writes: 3_000, reads: 0, storedGb: 0.1,
    followers: 100_000, followedNamespaces: 10, writesToFollowedNs: 3_000 / 10,
    cdn: { name: "Fastly", perMillion: 0.75, perGb: 0.12 },
  },
  {
    name: "Device fleet behind Bunny",
    about: "The same, behind Bunny (measured: the Worker ran about once per interval for 100 idle followers), which charges no request fees and $0.01/GB in Europe and North America (bunny.net/pricing/cdn, 2026-11-03)",
    writes: 3_000, reads: 0, storedGb: 0.1,
    followers: 100_000, followedNamespaces: 10, writesToFollowedNs: 3_000 / 10,
    cdn: { name: "Bunny", perMillion: 0, perGb: 0.01 },
  },
  {
    name: "Device fleet, long-poll collapsed by the CDN without the Worker",
    about: "The same fleet, with §7.7's long-poll URLs on a route Cloudflare's cache serves without running the Worker (the Worker as origin)",
    writes: 3_000, reads: 0, storedGb: 0.1,
    followers: 100_000, followedNamespaces: 10, writesToFollowedNs: 3_000 / 10,
    pollsBypassWorker: true, collapsePolls: true,
    // The origin still sees one poll per namespace, interval and CDN location.
    reads: 10 * 300 * (SECONDS_PER_MONTH / 20), cachedShare: 0,
  },
  {
    name: "Write-heavy ingest",
    about: "1,000 namespaces taking 10M writes a day (~115/s); reads elsewhere; 150 GB added a month",
    writes: 300 * M, reads: 0, storedGb: 150,
  },
  {
    name: "Write-heavy ingest, 7 rows a write (as first built)",
    about: "The same, with the first storage layout's resources table and extra index (about 7 rows written per append)",
    writes: 300 * M, reads: 0, storedGb: 150, rowsWrittenPerWrite: 7,
  },
];

const results = SCENARIOS.map((s) => {
  const u = usage(s);
  return { scenario: s.name, about: s.about, usage: u, ...cost(u) };
});

if (process.argv.includes("--json")) {
  console.log(JSON.stringify(results, null, 2));
} else {
  const fmt = (x) => (x < 0.005 ? "—" : `$${x.toFixed(2)}`);
  for (const r of results) {
    console.log(`\n${r.scenario}: ${fmt(r.total)}/month\n  ${r.about}`);
    for (const [k, v] of Object.entries(r.lines)) if (v >= 0.005) console.log(`  ${k.padEnd(22)} ${fmt(v).padStart(12)}`);
  }
}
