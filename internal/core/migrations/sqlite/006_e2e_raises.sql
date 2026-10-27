-- Migration: e2e raises
-- Created: 2026-10-27T13:41:22Z
-- Checksum: 948bb3c6e5537007ed5f6490197eaeef311c4590b819f21f652b7b785f835203
-- Chain: e007ae991705bb57a01b7010826f5300dbd84eae6a478b600785a95a602bc804
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- Raises to e2e (Addendum E Levels, e2e.go). One row per namespace that
-- became end-to-end by a config write rather than at its creation.
-- config_seq is the configuration that made it e2e, so the raising
-- namespace entry (config or batch), before which the raise lies, is the
-- first of ns_log with config_seq ≥ it (ns_log_ns_config); level is the
-- level before (0 none, 1 at-rest, 2 sealed), and epoch and pad, from
-- sealed, the last epoch and pad setting before the raise, which content
-- stored before it keeps (§E.2.2), 0 otherwise.
CREATE TABLE IF NOT EXISTS e2e_raises (
  ns         INTEGER PRIMARY KEY REFERENCES namespaces,
  config_seq INTEGER NOT NULL,
  level      INTEGER NOT NULL,
  epoch      INTEGER NOT NULL,
  pad        INTEGER NOT NULL,
  created    INTEGER NOT NULL
);
