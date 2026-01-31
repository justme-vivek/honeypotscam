import sqlite3

conn = sqlite3.connect('scam_sessions.db')
conn.row_factory = sqlite3.Row
c = conn.cursor()

print("=" * 60)
print("SCAM SESSIONS DATABASE")
print("=" * 60)

# Sessions
print("\n📁 SESSIONS:")
print("-" * 40)
c.execute("SELECT * FROM sessions ORDER BY created_at DESC LIMIT 5")
for row in c.fetchall():
    print(f"  Session: {dict(row)}")
    print()

# Messages - get column names first
c.execute("SELECT * FROM messages ORDER BY id DESC LIMIT 10")
rows = c.fetchall()
if rows:
    print("\n💬 MESSAGES:")
    print("-" * 40)
    for row in rows:
        data = dict(row)
        print(f"  {data}")
        print()

conn.close()
