-- Migration: purged namespaces keep name and purge id
-- Created: 2026-11-27T13:08:09Z
-- Checksum: 14c3279344fc54ae4c619aa92a540dfa52b70a85cff6ea766419e70933d661c3
-- Chain: 22fa5cedbdb25a17e25b24196725315bd4d106abf69130e60039674d36dbbd71
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- A purged namespace keeps only its name and the id of its purge-ns entry
-- (§5, §8.5, spec v0.91): its log, document chain, resources and
-- revisions, their ids and authors, the grant references of its entries
-- and what derives from them go (purgedNSTrim, nspurge.go, which a
-- namespace purge runs from now on). This deletes the same for the
-- namespaces purged before: their content was already gone, the rows
-- that recorded it go now. Each row keeps its name, which stays
-- reserved, the purge-ns id as head_id, frozen and purged set, and a
-- branch's base and base_at, which are its base's (the base's branch
-- entry) and place it in the base's /branches.
--
-- A table of the purges of other deployments' namespaces this deployment
-- has followed (§G.1): an import batch naming one in its source is 410
-- (purged), as for a local one (followedPurgeOf, purgefollow.go).
CREATE TABLE IF NOT EXISTS purged_sources (
  origin TEXT NOT NULL,
  src_ns TEXT NOT NULL,
  head   TEXT NOT NULL,
  PRIMARY KEY (origin, src_ns)
);
UPDATE namespaces SET head_id = (SELECT l.id FROM ns_log l WHERE l.seq = namespaces.head_seq)
  WHERE purged = 1 AND head_seq IS NOT NULL;
DELETE FROM head_history WHERE res IN (SELECT r.res FROM resources r JOIN namespaces n ON n.ns = r.ns WHERE n.purged = 1);
DELETE FROM blob_refs WHERE res IN (SELECT r.res FROM resources r JOIN namespaces n ON n.ns = r.ns WHERE n.purged = 1);
DELETE FROM blob_pending WHERE res IN (SELECT r.res FROM resources r JOIN namespaces n ON n.ns = r.ns WHERE n.purged = 1);
DELETE FROM blobs WHERE res IN (SELECT r.res FROM resources r JOIN namespaces n ON n.ns = r.ns WHERE n.purged = 1);
DELETE FROM blob_bytes WHERE owner IN (SELECT r.res FROM resources r JOIN namespaces n ON n.ns = r.ns WHERE n.purged = 1);
DELETE FROM snapshots WHERE res IN (SELECT r.res FROM resources r JOIN namespaces n ON n.ns = r.ns WHERE n.purged = 1);
DELETE FROM e2e_snapshots WHERE res IN (SELECT r.res FROM resources r JOIN namespaces n ON n.ns = r.ns WHERE n.purged = 1);
DELETE FROM heads WHERE res IN (SELECT r.res FROM resources r JOIN namespaces n ON n.ns = r.ns WHERE n.purged = 1);
DELETE FROM archives WHERE res IN (SELECT r.res FROM resources r JOIN namespaces n ON n.ns = r.ns WHERE n.purged = 1);
DELETE FROM deks WHERE res IN (SELECT r.res FROM resources r JOIN namespaces n ON n.ns = r.ns WHERE n.purged = 1);
DELETE FROM rev_epochs WHERE seq IN (SELECT v.seq FROM revisions v JOIN resources r ON r.res = v.res JOIN namespaces n ON n.ns = r.ns WHERE n.purged = 1);
DELETE FROM revisions WHERE res IN (SELECT r.res FROM resources r JOIN namespaces n ON n.ns = r.ns WHERE n.purged = 1);
DELETE FROM resources WHERE ns IN (SELECT ns FROM namespaces WHERE purged = 1);
DELETE FROM ns_grants WHERE ns IN (SELECT ns FROM namespaces WHERE purged = 1);
DELETE FROM ns_log WHERE ns IN (SELECT ns FROM namespaces WHERE purged = 1);
DELETE FROM ns_config WHERE ns IN (SELECT ns FROM namespaces WHERE purged = 1);
DELETE FROM epoch_keys WHERE ns IN (SELECT ns FROM namespaces WHERE purged = 1);
DELETE FROM e2e_epochs WHERE ns IN (SELECT ns FROM namespaces WHERE purged = 1);
DELETE FROM seal_counts WHERE ns IN (SELECT ns FROM namespaces WHERE purged = 1);
DELETE FROM sealed WHERE ns IN (SELECT ns FROM namespaces WHERE purged = 1);
DELETE FROM blob_epochs WHERE ns IN (SELECT ns FROM namespaces WHERE purged = 1);
DELETE FROM rotations_due WHERE ns IN (SELECT ns FROM namespaces WHERE purged = 1);
DELETE FROM purge_follow_waiting WHERE ns IN (SELECT ns FROM namespaces WHERE purged = 1);
DELETE FROM purge_follow_names WHERE ns IN (SELECT ns FROM namespaces WHERE purged = 1);
DELETE FROM purge_follows WHERE ns IN (SELECT ns FROM namespaces WHERE purged = 1);
DELETE FROM filtered_served WHERE ns IN (SELECT name FROM namespaces WHERE purged = 1);
DELETE FROM filtered_views WHERE ns IN (SELECT name FROM namespaces WHERE purged = 1);
DELETE FROM filtered_view_exps WHERE ns IN (SELECT name FROM namespaces WHERE purged = 1);
UPDATE namespaces SET frozen = 1, head_seq = NULL, config_seq = NULL, base_config_seq = NULL WHERE purged = 1;
