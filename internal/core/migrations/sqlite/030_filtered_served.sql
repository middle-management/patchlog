-- Migration: filtered served
-- Created: 2026-11-24T21:40:16Z
-- Checksum: 10ed916548ae8e4560514ace6266ebd46de5b6b184513fdecb03cf1d52677960
-- Chain: a04042ad304c0e62aa2eea74876a16dbffae94c47c9b7ffea1b532650ab27206
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- The namespaces a view of which has been served (§7.9, §8.3 CDN, v0.90):
-- a purge clears ns:{ns} at the CDN once one has, as filtered ranges are
-- tagged ns:{ns}. Kept for good, unlike filtered_views, whose rows are
-- swept a while after their cookies expire and which bearer reads at a
-- view URL never write.
CREATE TABLE IF NOT EXISTS filtered_served (ns TEXT PRIMARY KEY);
-- What was served before this table can't be told, so every namespace that
-- exists counts as served: a purge there clears ns:{ns} too, which costs at
-- most a tag purge where nothing was cached.
INSERT INTO filtered_served (ns) SELECT name FROM namespaces WHERE true ON CONFLICT (ns) DO NOTHING;
