-- Migration: clear at-rest digests
-- Created: 2026-10-27T13:44:23Z
-- Checksum: fa3e8371c5161daf32e413cfe8431ce479f0b58ca7879665b01784709d5f24cf
-- Chain: 5a0a190354f197b5a0353ef5a962b8c498742ee7b0ffa03489827cdf5d19ea27
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
      SELECT json_extract(c.doc, '$.encryption.level')
      FROM namespaces b JOIN ns_config c ON c.seq = b.config_seq
      WHERE b.name = CASE
        WHEN substr(n.name, 1, 1) <> '~' THEN n.name
        WHEN instr(substr(n.name, 2), '~') > 0 THEN substr(n.name, 2, instr(substr(n.name, 2), '~') - 1)
        ELSE substr(n.name, 2)
      END
    ) IN ('at-rest', 'sealed', 'e2e')
  )
);
