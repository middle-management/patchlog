-- Migration: remote levels
-- Created: 2026-10-27T13:41:34Z
-- Checksum: f8a59d2eebc5bc6cdd9ca56f07a9971d920247aa57fcf24c889236d8cf1d35d2
-- Chain: 31e681d72f23a9e4aa6046a07c79a288b71b74cf2abfb3ef7a91dc7da2b1261c
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- A remote branch whose source's level, as last seen in the log it
-- follows, is above its own (§G.5.2, remote_branch.go followLevel): level
-- is the source's (1 at-rest, 2 sealed, 3 e2e) after the entry id; lacks,
-- that this server can't hold it, so the source's resources answer 502
-- upstream (§1, upstream.go); rebase, that Levels refuse the raise, so the
-- branch needs a rebase. No row while the branch follows.
CREATE TABLE IF NOT EXISTS remote_levels (
  branch  bigint PRIMARY KEY REFERENCES namespaces,
  level   smallint NOT NULL,
  lacks   smallint NOT NULL,
  rebase  smallint NOT NULL,
  id      text NOT NULL,
  created bigint NOT NULL
);

-- A remote branch whose base's namespace document the follower reads once
-- more, as of its checkpoint (§G.5.2, remote_branch.go followRemote): one
-- created before the follower followed config entries, which moved its
-- checkpoint past them unread, so a raise made then would never be seen.
-- Migration 010 (remote catch-up) fills it once.
CREATE TABLE IF NOT EXISTS remote_catchup (
  branch bigint PRIMARY KEY REFERENCES namespaces
);
