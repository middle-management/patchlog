-- Migration: edge filters
-- Created: 2026-10-27T13:47:32Z
-- Checksum: 9129886ed509a2040399ebfc3286b813a96179879a70555af99ee38e336f2a6b
-- Chain: e12a7b808fe9f6e3958829ff571ee22f924030d6f05e5ab13d886f7585f4354f
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- edge_filters: the read filter behind each scope marker the service
-- minted an edge grant (a cookie) for, until the last of them expires
-- (edgegrants.go, readFilter).
CREATE TABLE IF NOT EXISTS edge_filters (marker TEXT PRIMARY KEY, filter TEXT NOT NULL, exp INTEGER NOT NULL);
