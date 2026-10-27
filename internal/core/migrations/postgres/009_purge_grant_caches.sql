-- Migration: purge grant caches
-- Created: 2026-10-27T13:44:23Z
-- Checksum: 8b8ddf8d101beb456f7f2abce271a6343475187050d95d62af1b25db77334ee3
-- Chain: 85581a7324ff81f0a96763adfebcd762d3b7338f6aa66267d92121078a626e4c
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
SELECT json_agg(tag ORDER BY name)::text, 0 FROM (
  SELECT n.name, 'ns:' || n.name AS tag, (row_number() OVER (ORDER BY n.name) - 1) / 100 AS chunk
  FROM namespaces n JOIN ns_config c ON c.seq = n.config_seq
  WHERE left(n.name, 1) <> '~'
    AND (c.doc::jsonb #>> '{encryption,level}') IN ('sealed', 'e2e')
    AND (c.doc::jsonb -> 'read') IS DISTINCT FROM '"public"'::jsonb
) g
GROUP BY chunk ORDER BY chunk;
