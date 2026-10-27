-- Migration: edge subjects and buckets
-- Created: 2026-10-27T13:45:57Z
-- Checksum: 27cab8a4d1db216f088c3b031ba2bb4bc475419f5a10078fca3b787fc0a109b1
-- Chain: a5c0ad6fb42acfbdaf71ff760f801b5d02c027a2dcd1f968f266d5d1f9a177f1
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- The state of a service's edge grants (Store), in its SQLite database
-- (the tree service's, the index's): edge_subjects, the subjects behind
-- each subject set the service minted an edge grant for, until the last of
-- them expires; edge_buckets, the exchangeRate buckets of its exchange, one
-- per principal (Store.Draw). The tree service's database has had
-- edge_subjects since before migrations were tracked (its own baseline).
CREATE TABLE IF NOT EXISTS edge_subjects (gs TEXT PRIMARY KEY, subjects TEXT NOT NULL, exp INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS edge_buckets (k TEXT PRIMARY KEY, tokens REAL NOT NULL, last INTEGER NOT NULL) WITHOUT ROWID;
