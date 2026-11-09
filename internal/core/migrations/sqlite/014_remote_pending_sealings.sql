-- Migration: remote pending sealings
-- Created: 2026-11-09T15:21:04Z
-- Checksum: fe7fa435f9fb9a68a0acc8cfdbf7363a528a49123c27a05a1b0701ad242e79a1
-- Chain: 971deb0b6fd98c0d39b025dacca5fc2fa9119dd46f884417fd1f35bb960057f7
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- Pre-raise sealings a remote branch lacks (§G.5.2 E3 sources, §G.3
-- Reading through; core preraise_pending.go): each sealing of content from
-- before its source's raise from sealed that the source didn't serve B
-- when asked, at creation or a later sync. shadow is the shadow holding
-- resource name; kind is entry or doc (the sealed table's kinds) of the
-- revision ref, or blob, of the blob id ref at its epoch URL; epoch is the
-- one its kid names, kid and pl (canonical JSON) what A seals it with, and
-- want the sha256 of the content it must open to (the canonical entry or
-- document, or the blob's bytes). rev_seq is the mirrored revision (for a
-- blob, the first one referencing it) a stored entry or document is
-- recorded with. answer is A's last answer: none, refused, transient,
-- unverified, or pruned with A's horizon, which is final (B answers 410
-- pruned). Each sync fetches the others again, and once one opens and
-- verifies it is stored (sealed, blob_epochs) and its row deleted; until
-- then B answers what needs it 502 upstream. updated is when answer was
-- last set, in Unix milliseconds.
CREATE TABLE IF NOT EXISTS remote_pending_sealings (
  shadow  INTEGER NOT NULL REFERENCES namespaces,
  name    TEXT    NOT NULL,
  kind    TEXT    NOT NULL,
  ref     TEXT    NOT NULL,
  epoch   INTEGER NOT NULL,
  rev_seq INTEGER NOT NULL,
  kid     TEXT    NOT NULL,
  pl      TEXT    NOT NULL,
  want    BLOB    NOT NULL,
  answer  TEXT    NOT NULL,
  horizon TEXT,
  updated INTEGER NOT NULL,
  PRIMARY KEY (shadow, name, kind, ref, epoch)
) WITHOUT ROWID;
