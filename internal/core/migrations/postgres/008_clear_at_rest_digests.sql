-- Migration: clear at-rest digests
-- Created: 2026-10-27T13:44:23Z
-- Checksum: b713b96b478e010b814151325400232fcd808416908ecc8f56c38021897a7fa3
-- Chain: 52140e1b615f87f27a92455ac0ca127757dcd8d82154918661dbf2001cf732a0
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- Drops the plaintext sizes and sha-256s of head documents (headMeta) that
-- versions before v0.73 stored for every level below sealed, from the
-- revisions of namespaces now encrypted at all and of remote shadows
-- serving such a branch (nsLevel): at rest a server leaves them out (§E.1
-- Stored digests), and in a namespace already at rest no raise
-- (encryptNamespace) or later write clears them. The level is read from
-- each namespace's current document, stored in plaintext; a shadow,
-- "~{branch}" or "~{branch}~{i}", has its remote branch's.
UPDATE revisions SET size = NULL, digest = NULL
WHERE digest IS NOT NULL AND res IN (
  SELECT r.res FROM resources r WHERE r.ns IN (
    SELECT n.ns FROM namespaces n
    WHERE (
      SELECT c.doc::jsonb #>> '{encryption,level}'
      FROM namespaces b JOIN ns_config c ON c.seq = b.config_seq
      WHERE b.name = CASE WHEN left(n.name, 1) <> '~' THEN n.name ELSE split_part(substr(n.name, 2), '~', 1) END
    ) IN ('at-rest', 'sealed', 'e2e')
  )
);
