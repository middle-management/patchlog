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
  rowsWrittenPerWrite: 7, // 6.0–7.7 observed; nslog, entries, resources and their indexes
  rowsReadPerWrite: 4,
  rowsReadPerRead: 2, // head reads come from memory; a revision read folds up to 16 entries
  activeMsPerWriteSparse: 20, // an object woken for one write stays active through its commit
  activeMsPerWriteBusy: 2.5, // under load, requests overlap
  activeMsPerRead: 3,
  bytesPerWrite: 512, // local SQLite, 0.5 KiB documents, snapshots every 16 entries
  pollIntervalS: 20, // §7.7's default interval
  objectGb: 0.128, // duration is billed at 128 MB per object: 7.66 GB-s per active minute measured
};

const SECONDS_PER_MONTH = 30 * 24 * 3600;

function usage(s) {
  const busy = s.busy ?? false;
  const followerPolls = (s.followers ?? 0) * (SECONDS_PER_MONTH / UNIT.pollIntervalS);
  // Each write answers every waiting follower of its namespace, which polls again.
  const wakePolls = (s.followers ?? 0) * (s.writesToFollowedNs ?? 0);
  const polls = followerPolls + wakePolls;
  const pollsAtObject = s.collapsePolls ? 0 : polls;
  const pollsAtWorker = s.pollsBypassWorker ? 0 : polls;
  const doReads = s.reads * (1 - (s.cachedShare ?? 0));
  return {
    workerRequests: s.writes + s.reads + pollsAtWorker,
    workerCpuMs: (s.writes + s.reads + pollsAtWorker) * UNIT.workerCpuMs,
    doRequests: s.writes + doReads + pollsAtObject,
    doGbSeconds:
      UNIT.objectGb *
      ((s.writes * (busy ? UNIT.activeMsPerWriteBusy : UNIT.activeMsPerWriteSparse) + doReads * UNIT.activeMsPerRead) / 1000 +
        // An object with a waiting follower is active all month (measured: 59.8 s of every minute).
        (s.followedNamespaces ?? 0) * SECONDS_PER_MONTH),
    rowsRead: s.writes * UNIT.rowsReadPerWrite + doReads * UNIT.rowsReadPerRead,
    rowsWritten: s.writes * (s.rowsWrittenPerWrite ?? UNIT.rowsWrittenPerWrite),
    storageGbMonth: s.storedGb ?? 0,
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
    name: "Collaborative SaaS, waits held without keeping objects awake",
    about: "The same, if each long-poll waited in the front Worker on a hibernatable WebSocket to the object instead of inside it (not built yet): the object isn't billed for duration while followers wait",
    writes: 30 * M, reads: 300 * M, cachedShare: 0.5, storedGb: 50,
    followers: 10_000, followedNamespaces: 0, writesToFollowedNs: 30 * M / 2_000 / 2,
  },
  {
    name: "Device fleet, long-poll through the Worker",
    about: "100,000 devices each long-polling one of 10 public namespaces; 100 writes a day; polls answered by the Worker and the object",
    writes: 3_000, reads: 0, storedGb: 0.1,
    followers: 100_000, followedNamespaces: 10, writesToFollowedNs: 3_000 / 10,
  },
  {
    name: "Device fleet, long-poll collapsed by the CDN",
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
    name: "Write-heavy ingest, 4 rows a write",
    about: "The same, after dropping the resources table and one index (about 4 rows written per append)",
    writes: 300 * M, reads: 0, storedGb: 150, rowsWrittenPerWrite: 4,
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
