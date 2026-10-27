-- Migration: baseline schema
-- Created: 2026-10-27T08:00:27Z
-- Checksum: 141a48e584ebc1e8efbe958493145d49e66ad0bf9e7b9251fd38e03d12f30e59
-- Chain: 6d06f20f5b273d72995f72b4ccb6c8d1e2d26b204f9e71839a7a67eac47d4b9a
--
-- IMPORTANT: Do not modify this file after commit. The checksum above
-- tracks the integrity of this migration. Any changes will be detected
-- and may cause deployment issues.
--

-- Second CDN purges of the index and tree services (Queue), in a service's
-- database.
-- IF NOT EXISTS throughout: a database created before migrations were
-- tracked (v0.22.0) already has all of it, and is adopted as is.

CREATE TABLE IF NOT EXISTS cdn_repurge (id INTEGER PRIMARY KEY AUTOINCREMENT, tags TEXT NOT NULL, due INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS cdn_repurge_due ON cdn_repurge (due);
