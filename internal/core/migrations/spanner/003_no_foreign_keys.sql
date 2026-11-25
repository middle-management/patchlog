-- Migration: no foreign keys
-- Created: 2026-11-25T11:45:53Z
-- Checksum: 6b0d10b7087f50cb217b5fb2dfbf1ae8269f259651df9d4db1295a15c7789160
-- Chain: 93d58cee11f609f8a566bdcdd130c797020476d53a9e24a19852d470a1c481b4
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- No foreign keys on Spanner (docs/SPANNER.md, the first bench run).
--
-- Each was a hidden index Spanner writes with every row of its table and a
-- check at commit: on the write path (revisions, heads, ns_log,
-- head_history) a good part of a group commit's inserts. The engine keeps
-- these references itself, as it must on every dialect (a row is written
-- only after the rows it names, in one transaction); Postgres and SQLite
-- keep their constraints. The names are those Spanner gives a constraint
-- written inline (REFERENCES), a hash of its definition, quoted: unquoted,
-- Spanner folds them to lower case, as Postgres does (the emulator matches
-- them whatever their case). A database whose names differ fails here
-- rather than keep a key.
ALTER TABLE archives DROP CONSTRAINT "FK_archives_resources_1DA95180EB9917FF_1";
ALTER TABLE blob_pending DROP CONSTRAINT "FK_blob_pending_resources_0E2D82FD4AD639CB_1";
ALTER TABLE blob_refs DROP CONSTRAINT "FK_blob_refs_resources_22C94FA61CE1454F_1";
ALTER TABLE blobs DROP CONSTRAINT "FK_blobs_resources_682A49A3B53CEFE5_1";
ALTER TABLE blobs DROP CONSTRAINT "FK_blobs_revisions_F3781F2ACC23C544_1";
ALTER TABLE e2e_epochs DROP CONSTRAINT "FK_e2e_epochs_namespaces_7DB25B6498D7BFA9_1";
ALTER TABLE e2e_snapshots DROP CONSTRAINT "FK_e2e_snapshots_revisions_1AF33900456DD326_1";
ALTER TABLE epoch_keys DROP CONSTRAINT "FK_epoch_keys_namespaces_FFF7AC900D11FB65_1";
ALTER TABLE head_history DROP CONSTRAINT "FK_head_history_ns_log_D8E1F9DBB4900F29_1";
ALTER TABLE head_history DROP CONSTRAINT "FK_head_history_resources_01EFFD083648DBB6_1";
ALTER TABLE head_history DROP CONSTRAINT "FK_head_history_revisions_64D111A360E5B8A1_1";
ALTER TABLE heads DROP CONSTRAINT "FK_heads_resources_0AE207E03D28A725_1";
ALTER TABLE namespaces DROP CONSTRAINT "FK_namespaces_namespaces_4697FF118030CC7D_1";
ALTER TABLE ns_config DROP CONSTRAINT "FK_ns_config_authors_A2C047459A3D5FEE_1";
ALTER TABLE ns_config DROP CONSTRAINT "FK_ns_config_namespaces_DB738AE43E2E04FC_1";
ALTER TABLE ns_log DROP CONSTRAINT "FK_ns_log_authors_A54826D0FF86FF17_1";
ALTER TABLE ns_log DROP CONSTRAINT "FK_ns_log_namespaces_3D74AF90A407B643_1";
ALTER TABLE purge_follow_names DROP CONSTRAINT "FK_purge_follow_names_namespaces_3B66FEC6FE2B4565_1";
ALTER TABLE purge_follow_waiting DROP CONSTRAINT "FK_purge_follow_waiting_namespaces_5267F5BC02EE414A_1";
ALTER TABLE purge_follows DROP CONSTRAINT "FK_purge_follows_namespaces_3196270DEA3C10A6_1";
ALTER TABLE resources DROP CONSTRAINT "FK_resources_namespaces_609C868F589AD20B_1";
ALTER TABLE revisions DROP CONSTRAINT "FK_revisions_authors_4D8926F9E5CD90B8_1";
ALTER TABLE revisions DROP CONSTRAINT "FK_revisions_resources_778C1B1D1C5B0D82_1";
ALTER TABLE rotations_due DROP CONSTRAINT "FK_rotations_due_namespaces_FD962D236AAA804B_1";
ALTER TABLE snapshots DROP CONSTRAINT "FK_snapshots_revisions_0F4C5A83D3E7126D_1";
