-- Migration: remote catch-up
-- Created: 2026-10-27T13:44:24Z
-- Checksum: f5d7fdc67107a1dc72dbaf6d4d846be79e2c54e76070d0d5717d3d420fc168cb
-- Chain: 07cfe84df65e69ec42f0c6627e0b763500347754e565c457c4f390ea16a1c815
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- Has the follower read once more, as of its checkpoint, the namespace
-- document of the base of every remote branch a database from before
-- v0.73's follower holds (remote_catchup, §G.5.2, followRemote): that
-- follower skipped config entries but moved the checkpoint past them, so a
-- raise of the base's level, or a read made non-public, seen by it was
-- never followed, and the branch would go on serving its source's content
-- below the level its source serves it at (§1, Addendum E Levels) until
-- the base wrote another config entry.
INSERT INTO remote_catchup (branch) SELECT branch FROM remote_bases;
