import sqlite3
from flask import g

DATABASE = 'your_database_file.db'  # Path to your database file

def get_db():
    """Connect to the database."""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(error=None):
    """Close the database connection."""
    db = g.pop('db', None)
    if db is not None:
        db.close()
