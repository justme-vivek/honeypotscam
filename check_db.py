import sqlite3

conn = sqlite3.connect('scam_sessions.db')
c = conn.cursor()

# List tables
c.execute("SELECT name FROM sqlite_master WHERE type='table'")
print("Tables:", c.fetchall())

# Get recent sessions
try:
    c.execute("SELECT * FROM sessions ORDER BY rowid DESC LIMIT 3")
    print("\nSessions:", c.fetchall())
except Exception as e:
    print(f"Sessions error: {e}")

# Get recent messages
try:
    c.execute("SELECT * FROM messages ORDER BY id DESC LIMIT 5")
    print("\nMessages:", c.fetchall())
except Exception as e:
    print(f"Messages error: {e}")

conn.close()
