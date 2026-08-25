import sqlite3


def find_user(cursor: sqlite3.Cursor, name: str):
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cursor.fetchone()
