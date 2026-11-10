-- Migration: v081 view keys
-- Created: 2026-11-10T16:13:53Z
-- Checksum: 83526368c6ef40ef6b45132e4600f92d7a4e23d49b1cca154c001a457b62e848
-- Chain: 4f647808b54da10c0aaac937842ce7ad60635b8d8132990b071d5b4751ecdb52
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- v0.81 (SERVICES §E.2.6 View keys): views are sealed under a key derived
-- from the view, ViewKey(K_n or K_r, view). Views stored before were sealed
-- under K_e or K_r and no reader opens them now: they are deleted, and
-- sealed again on demand (CacheResetStmts).
DELETE FROM sealed_views;
DELETE FROM sealed_view_tags;
