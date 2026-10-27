-- Migration: purge grant caches
-- Created: 2026-10-27T13:44:23Z
-- Checksum: 2f9e5244a5991e18422d541a1ea9bf7ca5db7c9cfec775fd3d440176eb024831
-- Chain: c4eda08eb4943dda7ea49634ffafb545f65df010207a27e9edb5b5d44963144e
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- Queues the purge of the public edge copies of the sealed and e2e
-- namespaces whose read isn't "public" (RH-44, Config.cachePublic):
-- versions before v0.73 cached every sealed and e2e namespace publicly,
-- and nothing purges the edge copies they left of those (a config write
-- purges ns:{ns} only when it changes cachePublic), which serve the
-- ciphertext and the metadata read "grant" hides (§E.2.5) until they
-- expire. Their ns:{ns} purges go to cdn_repurge, due at once, 100 tags a
-- row, which the leader sends (repurgeLoop) as it sends any write's second
-- purge. The level and read are read from each namespace's current
-- document, stored in plaintext; a remote branch's shadows ("~…") serve
-- under the branch's name, so they have none of their own.
INSERT INTO cdn_repurge (tags, due)
SELECT json_group_array(tag ORDER BY name), 0 FROM (
  SELECT n.name, 'ns:' || n.name AS tag, (row_number() OVER (ORDER BY n.name) - 1) / 100 AS chunk
  FROM namespaces n JOIN ns_config c ON c.seq = n.config_seq
  WHERE substr(n.name, 1, 1) <> '~'
    AND json_extract(c.doc, '$.encryption.level') IN ('sealed', 'e2e')
    AND json_extract(c.doc, '$.read') IS NOT 'public'
) g
GROUP BY chunk ORDER BY chunk;
