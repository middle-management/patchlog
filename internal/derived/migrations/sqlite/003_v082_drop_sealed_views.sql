-- Migration: v082 drop sealed views
-- Created: 2026-11-11T07:39:59Z
-- Checksum: 366fb11d4d4f61bc50a6224421f6f6133d2dfa7c62885524699b8dfcd8f9a550
-- Chain: 13394dea8e70f23462b68a125f4a6e7787ce5b5daf72619142da483ba20fb75e
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- v0.82 (SERVICES §E.2.6): every plaintext a view seals is canonical JSON
-- (What gets sealed), nothing derived from a revision is sealed before its
-- epoch is judged (Per-entry sealing), and a preview's entries are sealed
-- under the branch's keys. Views stored before may hold plaintexts that
-- aren't canonical, values sealed under an epoch never judged, or a
-- preview's under its base's keys: they are deleted, and sealed again on
-- demand (CacheResetStmts).
DELETE FROM sealed_views;
DELETE FROM sealed_view_tags;
