-- Migration: remote pending sealings
-- Created: 2026-11-09T15:21:04Z
-- Checksum: 0cedf3a4cddaa964d5a5ebaaf45b1e514f19723d6e8604bf8e808365f3d3a15e
-- Chain: 2aad9dbaa8fd615fa9b40efad67fbd861cd1908af3327dbbc63625b97520799e
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
  shadow  bigint NOT NULL REFERENCES namespaces,
  name    text   NOT NULL,
  kind    text   NOT NULL,
  ref     text   NOT NULL,
  epoch   bigint NOT NULL,
  rev_seq bigint NOT NULL,
  kid     text   NOT NULL,
  pl      text   NOT NULL,
  want    bytea  NOT NULL,
  answer  text   NOT NULL,
  horizon text,
  updated bigint NOT NULL,
  PRIMARY KEY (shadow, name, kind, ref, epoch)
);
