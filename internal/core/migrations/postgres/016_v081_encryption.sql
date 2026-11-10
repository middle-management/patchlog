-- Migration: v0.81 encryption
-- Created: 2026-11-10T13:14:40Z
-- Checksum: ce4555c099a730e79ed3723886d8cd8a01bec5cd64d2ed0ed60bde4f3dcd0366
-- Chain: 67c09352c6bfdf7058aa8e50b57dd62e0746f13ed02782988ae117eea9f2c50d
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- v0.81 encryption (Addendum E). Open refused, or purged, every namespace
-- and remote branch these marked before migrating (legacy_e2e.go): a
-- namespace is end-to-end from its creation or never (v0.78), so the
-- record of raises to e2e and a remote branch's pending pre-raise
-- sealings have no use left.
DROP TABLE IF EXISTS remote_pending_sealings;
DROP TABLE IF EXISTS e2e_raises;

-- Sealings, epochs of blobs and revisions stored for end-to-end
-- namespaces are dead: the server seals nothing there (§E.3).
DELETE FROM sealed WHERE ns IN (SELECT n.ns FROM namespaces n JOIN ns_config c ON c.seq = n.config_seq WHERE (c.doc::jsonb -> 'encryption' ->> 'level') = 'e2e');
DELETE FROM blob_epochs WHERE ns IN (SELECT n.ns FROM namespaces n JOIN ns_config c ON c.seq = n.config_seq WHERE (c.doc::jsonb -> 'encryption' ->> 'level') = 'e2e');
DELETE FROM rev_epochs WHERE seq IN (SELECT v.seq FROM revisions v JOIN resources r ON r.res = v.res
  JOIN namespaces n ON n.ns = r.ns JOIN ns_config c ON c.seq = n.config_seq WHERE (c.doc::jsonb -> 'encryption' ->> 'level') = 'e2e');
-- Plaintext documents kept below a horizon of a purged namespace.
DELETE FROM snapshots WHERE res IN (SELECT r.res FROM resources r JOIN namespaces n ON n.ns = r.ns WHERE n.purged = 1);

-- Namespace log ranges and long-poll answers (and v0.26.1's events) were
-- sealed under K_e itself; they are sealed again on request under K_n
-- (§E.2.1, §E.2.2). Grants stored before v0.73 under key "{gid}" are
-- served no more.
DELETE FROM sealed WHERE kind = 'range';
DELETE FROM sealed WHERE kind = 'grant' AND key NOT LIKE '%/v0.73';

-- kver: the key a stored sealing is under. 0, rows from before v0.81:
-- namespace documents and grants under K_e, which are sealed again under
-- K_n of their stored epoch when first served (sealed.go, resealKe);
-- 1, under K_n (namespace documents, grants) or K_r (the rest).
ALTER TABLE sealed ADD COLUMN kver bigint NOT NULL DEFAULT 0;

-- The message bound (§E.2.1): sealings counted per key, name '' for a
-- namespace's K_n, else the resource's K_r, of epoch epoch of namespace
-- ns. sealed counts the sealings made or handed out to instances in
-- blocks (sealcount.go); reserved what an epoch may still have to seal
-- after it ends (§E.2.2: a revision's document and log entry, a namespace
-- entry's range, a grant, a blob), which moves to sealed when sealed.
CREATE TABLE IF NOT EXISTS seal_counts (
  ns       bigint NOT NULL,
  epoch    bigint NOT NULL,
  name     text NOT NULL,
  sealed   bigint NOT NULL DEFAULT 0,
  reserved bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (ns, epoch, name)
);
-- Seeded from what is stored: the K_r sealings of documents and entries,
-- under their revisions' epochs, and of blobs, and 2 reserved for each
-- other revision whose epoch is fixed, less the sealings stored for it.
-- Sealings that were never stored (events, race losers) can't be known,
-- and are few against 2³².
INSERT INTO seal_counts (ns, epoch, name, sealed, reserved)
SELECT ns, epoch, name, SUM(sealed), SUM(reserved) FROM (
  SELECT s.ns AS ns, e.epoch AS epoch, s.name AS name, COUNT(*) AS sealed, 0 AS reserved
    FROM sealed s JOIN rev_epochs e ON e.seq = s.rev_seq
    WHERE s.kind IN ('doc', 'entry') AND s.name IS NOT NULL GROUP BY s.ns, e.epoch, s.name
  UNION ALL
  SELECT b.ns, b.epoch, b.name, COUNT(*), 0 FROM blob_epochs b GROUP BY b.ns, b.epoch, b.name
  UNION ALL
  SELECT r.ns, e.epoch, r.name, 0, SUM(2 - (SELECT COUNT(*) FROM sealed s WHERE s.ns = r.ns AND s.rev_seq = e.seq AND s.kind IN ('doc', 'entry')))
    FROM rev_epochs e JOIN revisions v ON v.seq = e.seq JOIN resources r ON r.res = v.res
    GROUP BY r.ns, e.epoch, r.name
) c GROUP BY ns, epoch, name;

-- Why a rotation is due: '' after a revocation (§E.2.4), 'bound' when a
-- key of the current epoch reached Options.SealRotateAt (§E.2.1).
ALTER TABLE rotations_due ADD COLUMN reason text NOT NULL DEFAULT '';
