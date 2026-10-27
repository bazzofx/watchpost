"""Search (`q`) behaviour: the FTS5 trigram fast path and its exact LIKE fallback.

The fast path must be interchangeable with the LIKE scan for the terms it serves, and must never
serve a term whose semantics would change — wildcard/escape characters, or terms shorter than a
trigram. These tests run against an in-memory database through the real `init_schema` path.
"""

import unittest

from watchpost import queries
from watchpost.db import connect, fts_available, init_schema


def _row(conn, message, i=0):
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, event_type, severity, message) "
        "VALUES (?, '2026-10-03T10:00:00.000Z', 'src', 'other', 'info', ?)",
        (f"2026-10-{i % 28 + 1:02d}T10:00:00.000Z", message),
    )


class FtsSearchTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def total(self, q):
        return queries.search_events(self.conn, {"q": q})["total"]

    def test_index_is_created_and_available(self):
        self.assertTrue(fts_available(self.conn))
        names = {r["name"] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("events_fts", names)

    def test_insert_becomes_searchable(self):
        _row(self.conn, "GET /api/orders/12345 -> 404 ua=curl/8.0")
        self.assertEqual(self.total("orders/12345"), 1)
        self.assertEqual(self.total("ORDERS/12345"), 1)   # case-insensitive, like LIKE
        self.assertEqual(self.total("12345"), 1)          # a partial token

    def test_literal_percent_uses_like_semantics(self):
        """q=50% must match a literal percent sign, exactly as the old LIKE search did."""
        _row(self.conn, "bad pw 50%")
        self.assertEqual(self.total("50%"), 1)
        self.assertEqual(self.total("%"), 1)

    def test_short_terms_fall_back_to_like(self):
        """A two-character term cannot be served by trigram FTS (it returns nothing); LIKE must."""
        _row(self.conn, "abc")
        self.assertEqual(self.total("ab"), 1)

    def test_underscore_is_a_literal_not_a_wildcard(self):
        _row(self.conn, "file_1.txt")
        self.assertEqual(self.total("file_1"), 1)

    def test_sql_injection_is_inert(self):
        _row(self.conn, "hello")
        self.assertEqual(self.total("'; DROP TABLE events;--"), 0)
        self.assertEqual(self.total("hello"), 1)  # the table is still there

    def test_delete_keeps_index_in_sync(self):
        _row(self.conn, "GET /unique/path -> 200")
        self.assertEqual(self.total("unique/path"), 1)
        self.conn.execute("DELETE FROM events")
        self.assertEqual(self.total("unique/path"), 0)

    def test_existing_rows_are_backfilled(self):
        """A database upgraded in place already holds events; the index must rebuild them once."""
        _row(self.conn, "GET /pre-existing -> 200")
        self.conn.execute("DROP TRIGGER trg_events_fts_ins")
        self.conn.execute("DROP TRIGGER trg_events_fts_del")
        self.conn.execute("DROP TABLE events_fts")
        init_schema(self.conn)
        self.assertEqual(self.total("pre-existing"), 1)

    def test_plain_like_fallback_when_index_is_missing(self):
        _row(self.conn, "GET /plain/like -> 200")
        self.conn.execute("DROP TABLE events_fts")
        self.assertFalse(fts_available(self.conn))
        self.assertEqual(self.total("plain/like"), 1)


class FtsRoutingTests(unittest.TestCase):
    def test_fts_friendly(self):
        self.assertTrue(queries._fts_friendly("abc"))
        self.assertTrue(queries._fts_friendly("orders/12345"))
        self.assertFalse(queries._fts_friendly("ab"))
        self.assertFalse(queries._fts_friendly("a%b"))
        self.assertFalse(queries._fts_friendly("a_b"))
        self.assertFalse(queries._fts_friendly("a\\b"))


if __name__ == "__main__":
    unittest.main()
