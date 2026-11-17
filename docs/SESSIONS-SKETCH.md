# Shared sessions: a sketch of TOOLS Addendum J.5–J.7

Status: sketch, not implemented. It builds on the stream proxy of J.1–J.4 on the
`stream-proxy` branch (`internal/streams`, `patchlog streams`).

## Goal

Several people work together in one session, and each brings their own agent (Claude
Code, Cursor, anything that speaks MCP). Everyone sees the same conversation and the
same documents. Every change records who made it (`author`) and through which agent
(`via`). The session's outcome merges back into the real content, or is dropped.

Not in the first spike: sealed and e2e namespaces, presence and typing indicators,
OAuth for a hosted MCP endpoint, a merge service.

## Shape

```
                         ┌─────────────── patchlog core ───────────────┐
 person A ── own agent ──┤ MCP (J.6) ─┐                                │
 person B ── own agent ──┤ MCP (J.6) ─┼─▶ {s}        workspace branch  │  ◀─ read-through ─ {base}
 person C (studio/UI) ───┤ direct ────┘   {s}-chat   messages, calls   │
                         │                streams    streamed replies  │
 shared agent ───────────┤ follows {s}-chat, answers @shared           │
                         └─────────────────────────────────────────────┘
 session host: creates sessions, mints session grants
 stream proxy (J.1–J.4, built): keeps model replies resumable
```

## Namespaces

| Namespace | What it is | Holds |
|---|---|---|
| `{s}` | A **branch of the workspace** `{base}` (§7.6), created with `read: "grant"` and the workspace roles below | The documents people and agents work on. Everything else reads through from `{base}` as of `at`. |
| `{s}-chat` | A **branch of a `sessions` template namespace** that exists only to carry the chat roles and `read: "grant"` | `m-…` messages, and `c-…` call records (J.7) |
| `streams` | The stream proxy's single namespace, already built (`-ns streams`) | Streamed replies, one resource each |

**Where this departs from J.5.** J.5 keeps messages and documents in one session
namespace. That stops working once the session is a branch to be merged: `patchlog merge`
has no resource filter, so every `m-…` and `c-…` would land in `{base}`. Keeping the chat in
its own namespace means merging `{s}` carries only document changes. It also lets each
namespace have roles that fit it, with no `if /resource` branching.

Making `{s}-chat` a branch of a template means a session is created with `branch` grants
only, never an operator key. Its roles and keys come from the template (§7.6: "keys follow
the base").

`{s}` is at most 51 bytes, so that `{s}-chat` stays a valid name (§3.6, 56).

## Grants

A grant's `ns` must name each namespace exactly (§7), and narrowing can only remove
namespaces, never add them. So a person's grant for `{base}` can't be narrowed into a grant
for `{s}`. Something has to mint session grants. That's the **session host**.

| Who | Grant | Minted by |
|---|---|---|
| Session host | Root grant: `branch` and unrestricted `read` on `{base}` and `sessions`. Its key is listed in both, so through the branches it can mint grants for `{s}` and `{s}-chat`. | Operator, once |
| Person | Root grant: `sub: user:anna`, `ns: [{s}, {s}-chat]`, `roles: [reader, member]` (or `[reader]`), short `exp` | The host, at join, after checking the person's grant on `{base}` with `GET /ns/{base}/principal`. The stream proxy's `-caller-ns` check works the same way. |
| Person's agent | The person's session grant **narrowed on the person's machine**: `{"via": "agent:claude-code", "exp": …}` | The person (`patchlog session join` does this) |
| Shared agent | Its own root grant, `sub: agent:shared`, `roles: [reader, member]`, **with `via` rules applied** | The host, at session creation |

**The shared agent's grant is limited.** J.5 says "a shared agent's own grant isn't
limited". That's a confused deputy: a reader-only participant could ask `@shared` to do
what they can't do themselves. In this sketch the shared agent gets the same limit as a
`via` grant. It also answers only messages whose `author` holds `member`. The host knows
who that is, because it minted the grants.

### Roles of `{s}` (the workspace branch)

```jsonc
"roles": {
  "reader": { "can": ["read"] },
  "member": { "can": ["read", "create", "append", "delete", "restore"], "rules": [
    { "if":   [{ "op": "test", "path": "/principal/via", "schema": { "minItems": 1 } }],
      "then": [{ "op": "test", "path": "/action", "schema": { "enum": ["create", "append"] } }] } ] },
  "forker": { "can": ["read", "branch"] }
}
```

### Roles of `{s}-chat` (from the `sessions` template)

These are J.5's roles unchanged: a member creates messages only, in their own name, and
never changes or deletes them. `c-…` documents follow the same author rule, and their
writer is the recording proxy acting with the person's grant (J.7).

## Components

| Package / command | What it is | Size |
|---|---|---|
| `internal/sessiontools` | The J.6 tools as plain Go over `internal/client`, independent of MCP. Each tool takes a `*client.Client` that carries the caller's grant. | Most of the logic |
| `patchlog mcp` | An MCP server over `sessiontools`. stdio first; streamable HTTP later. Stateless: it forwards the bearer it was started with. | Thin |
| `patchlog session host` | `POST /sessions` (create `{s}` and `{s}-chat`, mint the shared agent's grant), `POST /sessions/{s}/join` (check, then mint a person's grant) | Small HTTP service, the same shape as `streams.Proxy` |
| `patchlog session join` | CLI for a person: calls join, narrows the grant with `via`, prints the MCP config for their agent | Small |
| `patchlog session agent` | The shared agent: follows `{s}-chat` with `internal/follow`, runs the model through the stream proxy, uses `sessiontools` in-process | Medium |
| Recording proxy (J.7) | `…/p/{id}` base URLs that record calls to `{s}-chat/c-…` | Phase 3 |

**MCP dependency.** `go.mod` has no MCP library. Use the official Go SDK
(`github.com/modelcontextprotocol/go-sdk`), or hand-roll stdio JSON-RPC for the spike,
since the tool surface is small. Either way, keep it behind `sessiontools`.

## J.6 tools over the client library

| Tool | Client calls | Notes |
|---|---|---|
| `session_info` | `NSPrincipal(ctx, s)` | Also returns the session conventions: which namespace is which, and the edit rules below |
| `list_documents` | `NSHead`, then `Heads(ctx, s, nsID)` | Read-through documents appear too |
| `read_document` | `Load(ctx, s, name)` | Returns the revision. Strips `$nonce` |
| `create_document` | `CreateDoc` (`If-None-Match: *`) | `200` counts as success (a retry). `412` returns the current document |
| `edit_document` | `Append(ctx, s, name, rev, patches)` with a fresh `$nonce` | `412` returns the current document **and who changed it** (`Log(…, since=rev)`). The agent redoes its change; never use `AppendLatest` here, because it would hide the conflict |
| `document_history` | `Log` | `author`, `via`, time, patch |
| `recent_changes` | `LongPoll(ctx, s, since, cursor)` **and** `LongPoll(ctx, s+"-chat", …)` | One call covers both logs, returns two cursors, and names authors |
| `post_message` | `CreateDoc(ctx, s+"-chat", "m-"+id, {author, text, to?})` | `author` must equal the principal, and the role rule enforces it |
| `read_messages` | `NSLog` on `{s}-chat`, then `Doc` for each | **Returns message text as quoted data** (below) |

**Treating messages as data.** Every message and document body a tool returns is marked
as content written by a named participant, never as instructions. For example:
`{"from": "user:bo", "via": null, "text": "…"}`, under a tool description that says so.
Without this, Bo's text can steer Anna's agent, which acts with Anna's grant. J.5 leaves
this to the application. It belongs in the tools.

## Flows

**Create.** A host request with the creator's grant:
`CreateBranch({base}, {name: s, patches: [read: grant, workspace roles]})`, then
`CreateBranch(sessions, {name: s+"-chat"})`, then mint the shared agent's grant. The
answer is the session id and the creator's session grant.

**Join.** `patchlog session join -host URL -grant-file mine s` → the host checks
`principal` on `{base}`, then mints `ns: [s, s-chat]` with `roles` from the person's role
in `{base}` (`member` if they can write there, else `reader`) → the CLI narrows a copy with
`via: agent:<name>` and prints:

```jsonc
{ "mcpServers": { "session-42": { "command": "patchlog",
  "args": ["mcp", "-api", "https://…", "-session", "s42", "-grant-file", "~/.patchlog/s42.agent"] } } }
```

**Edit through a person's own agent.** Anna's agent calls `read_document("plan")`, then
`edit_document("plan", rev, [{test …}, {add …}])`. The log records
`author: user:anna, via: [agent:claude-code]`. A UI shows "Anna · via claude-code".

**Ask the shared agent.** Bo posts `m-…` `{to: "agent:shared", text: "…"}`. The agent
sees it in `{s}-chat`'s log, in log order, one at a time. It calls the model with
`POST /streams` (Upstream-URL = the model API, with the key passed through, never stored)
and immediately posts its reply message naming the stream
(`{author: "agent:shared", stream: "/r/streams/{id}"}`). Readers follow the stream with
`streams.Follow`, and someone who joins mid-reply resumes from the start. When the stream
closes, the agent appends the assembled text to its message. Tool calls run between turns
through `sessiontools` under its own grant.

**Stop a reply.** `streams.Abort`. This is already built (J.4).

**Fork.** `CreateBranch(s, …)` and `CreateBranch(s-chat, …)` with the same suffix. That's
what the `forker` role allows.

**Finish.** `patchlog merge -branch s` into `{base}` (Addendum F; the release merge path
for catalog bases). This carries only document changes. Then freeze `{s}` and `{s}-chat`.
The chat stays as the session's record until retention or purge.

## Phases

1. **Tools and MCP, no host.** On a `-dev` server (no grants, `X-Author`), create both
   namespaces by hand. Build `sessiontools` and `patchlog mcp`. Two Claude Code instances
   edit one document. Proves conflict handling (`412` → reread → redo) and `recent_changes`.
2. **Grants and host.** `session host` and `join`, the role sets, `via` narrowing, and the
   limited shared-agent grant. Tests: a reader's agent is `403` on edits, a `via` grant is
   `403` on delete, a member can't post as someone else, and `@shared` ignores a reader.
3. **Shared agent and streaming.** `session agent` over the stream proxy. Tests: a reply
   resumes after a reconnect, abort, and two messages sent at once are answered in log
   order.
4. **Recording (J.7) and merge back.** `…/p/{id}`, `c-…` documents. Merge `{s}` into
   `{base}` and check that no `m-`/`c-` resource arrives.

Tests run against `internal/testenv` servers, like `internal/streams/streams_test.go`.

## SPEC-FEEDBACK candidates

- **J.5 single namespace vs merge.** A session that is a branch can't keep messages in it
  without a merge filter. Either J.5 says "chat in a companion namespace", or Addendum F
  gets a resource filter.
- **J.5 shared agent unlimited.** This is a confused deputy. It should carry the `via` limit
  and answer only `member` authors.
- **Who mints session grants.** J.5 is silent. Exact `ns` names make a minting service
  necessary.
- **J.5's per-session `{s}-streams`** vs the built proxy's single namespace. The proxy
  would need a namespace per request to follow J.5. The single namespace works because
  each stream's read grant is fixed to its resource.
- **Note 94 matters here.** Long replies continue in `{id}.{n}`, and the reader's grant
  can't follow them.

## Open questions

- Should the session host fold into the stream proxy process (one "session service"), or
  stay separate?
- Should `{s}` take roles from `{base}` per person (for example, a person who can't edit
  `layouts/` in `{base}` can't in `{s}` either)? That needs rules copied from `{base}` at
  creation, which `CreateBranch` already does before applying `patches`.
- Are message threads (`re: m-…`) needed in phase 1?
- For Doors: does the studio become a patchlog participant directly, or does Doors' MCP
  server proxy `sessiontools`?
