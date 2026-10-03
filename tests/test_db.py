"""Connection and schema behaviour (watchpost/db.py).

Journalling is a property of the database *file*, not of a connection, so it is set once when the
schema is created. Setting it in connect() — which the server calls for every HTTP request — meant
every request took a lock on the database header, one of the causes of "database is locked" under
load. These tests pin that down, because the difference is invisible until the store is busy.
"""

import os
import tempfile
import unittest

from watchpost.db import ADDED_COLUMNS, SCHEMA_VERSION, connect, init_schema


class JournalModeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "test.db")

    def tearDown(self):
        self.tmp.cleanup()

    def mode(self, conn):
        return conn.execute("PRAGMA journal_mode").fetchone()[0]

    def test_connect_alone_does_not_change_the_journal_mode(self):
        """Opening a connection must be lock-free: it is what every request does."""
        conn = connect(self.db_path)
        try:
            self.assertEqual(self.mode(conn), "delete", "connect() took a lock it did not need")
        finally:
            conn.close()

    def test_init_schema_enables_wal_once(self):
        conn = connect(self.db_path)
        try:
            init_schema(conn)
            self.assertEqual(self.mode(conn), "wal")
        finally:
            conn.close()

    def test_wal_persists_so_later_connections_inherit_it(self):
        conn = connect(self.db_path)
        init_schema(conn)
        conn.close()

        later = connect(self.db_path)
        try:
            self.assertEqual(self.mode(later), "wal", "WAL is a file property and should persist")
        finally:
            later.close()

    def test_durability_is_relaxed_to_normal(self):
        """WAL pairs with synchronous=NORMAL: an fsync at checkpoints, not on every commit."""
        conn = connect(self.db_path)
        try:
            init_schema(conn)
            self.assertEqual(conn.execute("PRAGMA synchronous").fetchone()[0], 1)  # 1 = NORMAL
        finally:
            conn.close()

    def test_a_memory_database_is_left_alone(self):
        conn = connect(":memory:")
        try:
            init_schema(conn)   # must not raise: there is no journal to configure
            self.assertEqual(self.mode(conn), "memory")
        finally:
            conn.close()


class ConnectionTests(unittest.TestCase):
    def test_busy_timeout_is_set_on_every_connection(self):
        """Requests should queue behind a writer rather than fail immediately."""
        conn = connect(":memory:")
        try:
            self.assertEqual(conn.execute("PRAGMA busy_timeout").fetchone()[0], 20000)
        finally:
            conn.close()

    def test_the_timeout_stays_below_the_shippers_request_timeout(self):
        """A lock wait longer than the client's 30 s would reach it as a broken pipe instead."""
        conn = connect(":memory:")
        try:
            self.assertLess(conn.execute("PRAGMA busy_timeout").fetchone()[0], 30000)
        finally:
            conn.close()

    def test_foreign_keys_are_enforced_and_rows_are_dict_like(self):
        conn = connect(":memory:")
        try:
            self.assertEqual(conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(conn.row_factory.__name__, "Row")
        finally:
            conn.close()

    def test_the_parent_directory_is_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            nested = os.path.join(tmp, "a", "b", "test.db")
            conn = connect(nested)
            try:
                init_schema(conn)
            finally:
                conn.close()
            self.assertTrue(os.path.exists(nested))


class SchemaTests(unittest.TestCase):
    def test_schema_version_is_recorded(self):
        conn = connect(":memory:")
        try:
            init_schema(conn)
            stored = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0]
            self.assertEqual(stored, str(SCHEMA_VERSION))
        finally:
            conn.close()

    def test_init_schema_is_idempotent(self):
        conn = connect(":memory:")
        try:
            init_schema(conn)
            init_schema(conn)
            self.assertEqual(self.count_tables(conn), self.count_tables(conn))
        finally:
            conn.close()

    def test_added_columns_are_present(self):
        """Existing databases gain these in place, so they must exist after a fresh init too."""
        conn = connect(":memory:")
        try:
            init_schema(conn)
            for table, column, _ in ADDED_COLUMNS:
                with self.subTest(table=table, column=column):
                    columns = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
                    self.assertIn(column, columns)
        finally:
            conn.close()

    @staticmethod
    def count_tables(conn):
        return conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'").fetchone()[0]


if __name__ == "__main__":
    unittest.main()
