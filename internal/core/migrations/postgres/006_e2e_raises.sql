-- Migration: e2e raises
-- Created: 2026-10-27T13:41:22Z
-- Checksum: 4db860b177f627a35cabae1afb7e8483586be66ccde5de9d76540a4d9bded909
-- Chain: 1e5993d8089ab1d37446a47ef8064e012bc2dd4686a5a2014458c11e430ce328
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
  ns         bigint PRIMARY KEY REFERENCES namespaces,
  config_seq bigint NOT NULL,
  level      bigint NOT NULL,
  epoch      bigint NOT NULL,
  pad        bigint NOT NULL,
  created    bigint NOT NULL
);
