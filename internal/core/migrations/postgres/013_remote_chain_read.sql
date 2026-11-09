-- Migration: remote chain read
-- Created: 2026-11-09T10:15:56Z
-- Checksum: 961db2852c566010d6d64d2ecf1d4ea964b88d040614601ab0dec42f6674313f
-- Chain: e2dc2f6dd0d526b185e8d24b35c5ccb92aabc481dd592ba478cd064a3444debf
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
  shadow bigint PRIMARY KEY REFERENCES namespaces,
  ok     smallint NOT NULL,
  at     bigint NOT NULL
);
