-- Migration: ns_log derived bodies and grant refs
-- Created: 2026-11-27T08:42:20Z
-- Checksum: 30ebfb7cd23698ff587d5a6d7ec912e9a1bc681e121aced3ad610194e54fcb10
-- Chain: 21315837752c571ac47033d822bc4631f1c39a471af3952b58b5ffbcc0a8eaf2
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- Derived ns_log columns and grant references by number (docs/capacity/
-- storage, CHANGELOG):
--
-- ns_log.body of a head or tombstone entry is stored empty, and its created
-- 0, when the entry is exactly { kind, resource, target } of the revision
-- its write inserted (entrybody.go): the body is rebuilt from l.kind, the
-- name of l.res and the id of l.target_seq, byte for byte as hashed (§3.5),
-- and created is the revision's, written in the same transaction. The
-- column stays NOT NULL (SQLite can't drop it without rebuilding ns_log), so
-- the empty string stands for NULL; it costs the same. Rows written before
-- keep their bodies: nothing is rewritten.
--
-- grants.ref numbers each stored grant once; ns_log.grant_ref and
-- revisions.grant_ref name a grant by it in place of the 20-byte
-- grant_id, which rows written before keep (reads take either). ref is an
-- explicit column, since VACUUM may renumber a rowid that isn't an INTEGER
-- PRIMARY KEY.
ALTER TABLE grants ADD COLUMN ref INTEGER;
UPDATE grants SET ref = rowid;
CREATE UNIQUE INDEX IF NOT EXISTS grants_ref ON grants (ref);
ALTER TABLE ns_log ADD COLUMN grant_ref INTEGER;
ALTER TABLE revisions ADD COLUMN grant_ref INTEGER;
-- The entries recording a grant by number, as ns_log_by_grant does by id
-- (grants.go, archive.go).
CREATE INDEX IF NOT EXISTS ns_log_by_grant_ref ON ns_log (grant_ref, ns, seq) WHERE grant_ref IS NOT NULL;
