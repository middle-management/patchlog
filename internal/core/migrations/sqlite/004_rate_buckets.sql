-- Migration: rate buckets
-- Created: 2026-10-27T13:41:22Z
-- Checksum: e33b1818fcc43debd06ee87946daf60008b6b04e3dd578607b435b617380af64
-- Chain: 25c4f2d88ddca720db3931491a3c02c8780d4765d4139f2998085c2f3e1562d6
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- The rate-limit buckets of §6.6, shared by the instances of a deployment
-- on Postgres (ratebuckets.go). A SQLite database is written by one
-- instance, which keeps its buckets in memory and leaves this table empty.
-- key is the bucket (auth.go), tokens what it held when last drawn on,
-- last when (Unix microseconds), and rate and burst those it was drawn on
-- under, for the sweep; a bucket without a row is full.
CREATE TABLE IF NOT EXISTS rate_buckets (
  key    BLOB    PRIMARY KEY,
  tokens REAL    NOT NULL,
  last   INTEGER NOT NULL,
  rate   REAL    NOT NULL,
  burst  REAL    NOT NULL
);
