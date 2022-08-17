"""
This code needs to be run in order to create a new/fresh sqlite3 database
"""
import sqlite3
from os import path


directory = path.dirname(path.abspath(__file__))
parent_directory = path.dirname(directory)
schema_path = path.join(directory, 'schema.sql')
db_path = path.join(parent_directory, 'database.db')

connection = sqlite3.connect(db_path)

with open(schema_path) as f:
    connection.executescript(f.read())

# cur = connection.cursor()
# cur.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', ('user1', 'pass1'))
# result = cur.execute('SELECT id FROM users WHERE username = ?', ('user1', )).fetchone()
# print(result)

connection.commit()
connection.close()
