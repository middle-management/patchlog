-- Migration: remote levels
-- Created: 2026-10-27T13:41:34Z
-- Checksum: b4cdd62e3803abb7015d395a3a2d171ec9a6067f21e8fcbdb4e352f96493a45a
-- Chain: a7c4d9c571100e218a07304a85971b4419c5ba80c8e7aa3bb18ebc6a262d782c
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
  branch  INTEGER PRIMARY KEY REFERENCES namespaces,
  level   INTEGER NOT NULL,
  lacks   INTEGER NOT NULL,
  rebase  INTEGER NOT NULL,
  id      TEXT NOT NULL,
  created INTEGER NOT NULL
);

-- A remote branch whose base's namespace document the follower reads once
-- more, as of its checkpoint (§G.5.2, remote_branch.go followRemote): one
-- created before the follower followed config entries, which moved its
-- checkpoint past them unread, so a raise made then would never be seen.
-- Migration 010 (remote catch-up) fills it once.
CREATE TABLE IF NOT EXISTS remote_catchup (
  branch INTEGER PRIMARY KEY REFERENCES namespaces
);
