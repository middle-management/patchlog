-- Migration: remote chain read
-- Created: 2026-11-09T10:15:56Z
-- Checksum: 80412858621922a392c8caaf698f207e36d58f3bb74fc1a86c33fde0eeca05b0
-- Chain: 559d1fdc7d4b02d9a810f548c7a0de847e51b30672104da4e31cbe2dde702467
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- Whether the follower's latest read of the current namespace document of
-- a deeper base of a remote branch, one below its base in base.chain (a
-- shadow other than the first, remoteShadows), succeeded (§G.5.2 E3
-- sources, remote_branch.go followChainEpochs): ok 1 on success, 0 after
-- any failure, and no row until the first success after creation. A
-- branch's /keys relays that base's keyring entries and pre-raise keys,
-- and uses its last-seen epoch, only while ok is 1 (e2e.go baseEpochs).
-- at is when that read was made, in Unix milliseconds.
CREATE TABLE IF NOT EXISTS remote_chain_read (
  shadow INTEGER PRIMARY KEY REFERENCES namespaces,
  ok     INTEGER NOT NULL,
  at     INTEGER NOT NULL
);
