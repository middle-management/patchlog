// A small patchlog client: load a document, and save patch sets with the
// rebase of §11. Plain `fetch`, so it runs in browsers (the Worker answers
// CORS, §7) and in Node.
//
// Why rebase instead of fresh head reads: head pointers are cacheable for
// a second (§9, `s-maxage=1, stale-while-revalidate=5`), so behind a CDN a
// head read just after someone else's write can be stale, and a save with
// `If-Match` on it gets `412`. That `412` names the real head, and a pinned
// revision (`…/rev/{id}`) is immutable, so no cache can serve a stale one:
// the client loads that revision and resends the same patches. A stale read
// costs one extra round trip, never a wrong answer.
//
//   const doc = await load(base, "site", "home");
//   const saved = await save(base, "site", "home", doc, patches, { author: "studio" });
//   // saved = { head, doc, rebased }
//
// Patches that must not land on changed data start with `test` ops of the
// values they saw (§11, conflict safety): after a rebase those fail with 422
// instead of overwriting someone else's change.

/** Loads a document: `{ head, doc }`, or `{ head, gone: true }` if deleted. */
export async function load(base, ns, name, { fetch: f = fetch } = {}) {
  const r = await f(`${base}/r/${ns}/${name}`);
  if (r.status === 410) {
    const body = await r.json();
    return { head: body.tombstone, doc: undefined, gone: true };
  }
  if (!r.ok) throw await problem(r);
  return { head: r.headers.get("x-revision") ?? unquote(r.headers.get("etag")), doc: await r.json() };
}

/** Loads one revision; immutable, so safe to read through any cache. */
export async function loadRevision(base, ns, name, id, { fetch: f = fetch } = {}) {
  const r = await f(`${base}/r/${ns}/${name}/rev/${id}`);
  if (!r.ok) throw await problem(r);
  return { head: id, doc: await r.json() };
}

/**
 * Saves `patches` on top of `state.head` (`{ head }` from `load`, or
 * `{ head: null }` to create). On `412` it loads the head the server names
 * and resends the same patches, up to `retries` times. A lost response is
 * resent unchanged, which the server answers as an idempotent retry (§7.2).
 * Resolves to `{ head, doc, rebased }`; throws an Error with `status` and
 * `body` for anything else (`409 frozen`, `410`, `422`, `428`, …).
 */
export async function save(base, ns, name, state, patches, opts = {}) {
  const { author, gesture, undoes, retries = 5, fetch: f = fetch } = opts;
  let head = state.head;
  let rebased = 0;
  for (let attempt = 0; ; attempt++) {
    const headers = { "Content-Type": "application/json-patch+json" };
    if (head) headers["If-Match"] = `"${head}"`;
    else headers["If-None-Match"] = "*";
    if (author) headers["X-Author"] = author;
    if (gesture) headers["Gesture"] = gesture;
    if (undoes) headers["Undoes"] = undoes;
    let r;
    try {
      r = await f(`${base}/r/${ns}/${name}`, { method: "PATCH", headers, body: JSON.stringify(patches) });
    } catch (e) {
      // The write may have landed: resend it unchanged.
      if (attempt < retries) continue;
      throw e;
    }
    if (r.status === 201 || r.status === 200) {
      const id = unquote(r.headers.get("etag"));
      const { doc } = await loadRevision(base, ns, name, id, { fetch: f });
      return { head: id, doc, rebased };
    }
    if (r.status === 412 && attempt < retries) {
      const body = await r.json();
      if (!body.head) throw Object.assign(new Error(body.message ?? "412"), { status: 412, body });
      // Rebase: the server's head, then the same patches again.
      head = body.head;
      rebased++;
      continue;
    }
    throw await problem(r);
  }
}

function unquote(etag) {
  return etag?.replace(/^W\//, "").replace(/^"|"$/g, "") ?? null;
}

async function problem(r) {
  let body;
  try { body = await r.json(); } catch { body = undefined; }
  return Object.assign(new Error(body?.message ?? `HTTP ${r.status}`), { status: r.status, body });
}
