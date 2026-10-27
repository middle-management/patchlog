-- Migration: ns conf
-- Created: 2026-10-27T13:47:32Z
-- Checksum: a8ae5f5f048d3f1bdd5df413e2d135c5a592fc2c45c66c5bc69a62802e8c958c
-- Chain: 46e90fd520bb289897c2508c3040754fcd6cbc731ad04758f29cf439fa78046c
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- ns_conf: per namespace, the read mode (public) and the encryption level
-- the index last applied, against which a config entry is found to make
-- the namespace private or raise it to sealed or e2e (§9, Index.narrowed).
CREATE TABLE IF NOT EXISTS ns_conf (ns TEXT PRIMARY KEY, public INTEGER NOT NULL, level TEXT NOT NULL);
