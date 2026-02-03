#!/usr/bin/env python3
"""
Database Viewer for Honeypot Scam Detection System
===================================================
View data from all 3 databases:
  python view_db.py --current     # Show current_session.db
  python view_db.py --archive     # Show chat_sessions.db  
  python view_db.py --scams       # Show scam_sessions.db
  python view_db.py --all         # Show all databases
  python view_db.py               # Default: show all
"""

import sqlite3
import json
import argparse
import os
from datetime import datetime

# Database paths
CURRENT_SESSION_DB = "current_session.db"
CHAT_SESSIONS_DB = "chat_sessions.db"
SCAM_SESSION_DB = "scam_session.db"  # Renamed from scam_sessions.db

def print_header(text):
    print(f"\n{'='*70}")
    print(f"  {text}")
    print(f"{'='*70}")

def print_subheader(text):
    print(f"\n{'-'*50}")
    print(f"  {text}")
    print(f"{'-'*50}")

def db_exists(db_path):
    return os.path.exists(db_path)

# ============================================================================
# 1. CURRENT SESSION DB VIEWER
# ============================================================================

def view_current_session():
    """View current_session.db - Active sessions being processed."""
    print_header("📍 CURRENT SESSION DB (Active Sessions)")
    
    if not db_exists(CURRENT_SESSION_DB):
        print("  ⚠️  Database not found: current_session.db")
        return
    
    conn = sqlite3.connect(CURRENT_SESSION_DB)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Show sessions
    print_subheader("🔹 Active Sessions")
    try:
        cursor.execute("SELECT * FROM session_info ORDER BY updated_at DESC")
        sessions = cursor.fetchall()
        
        if not sessions:
            print("  (No active sessions)")
        else:
            for s in sessions:
                scam_status = "🚨 CONFIRMED SCAM" if s['is_confirmed_scam'] else f"⚡ {s['scam_flags']} flag(s)"
                print(f"\n  Session: {s['session_id']}")
                print(f"    Channel: {s['channel']} | Language: {s['language']} | Locale: {s['locale']}")
                print(f"    Scam Status: {scam_status}")
                print(f"    Created: {s['created_at']} | Updated: {s['updated_at']}")
    except sqlite3.OperationalError as e:
        print(f"  ⚠️  Table error: {e}")
    
    # Show messages
    print_subheader("🔹 Messages in Active Sessions")
    try:
        cursor.execute("""
            SELECT * FROM messages ORDER BY session_id, id LIMIT 20
        """)
        messages = cursor.fetchall()
        
        if not messages:
            print("  (No messages)")
        else:
            for m in messages:
                sender_icon = "🤖" if m['is_response'] else "👤"
                scam_flag = " 🚩" if m['is_scam_flag'] else ""
                text_preview = m['text'][:60] + "..." if len(m['text']) > 60 else m['text']
                print(f"  [{m['session_id'][:8]}...] {sender_icon} {m['sender']}: {text_preview}{scam_flag}")
    except sqlite3.OperationalError as e:
        print(f"  ⚠️  Table error: {e}")
    
    # Show extracted intelligence
    print_subheader("🔹 Extracted Intelligence")
    try:
        cursor.execute("SELECT * FROM extracted_intel")
        intel_rows = cursor.fetchall()
        
        if not intel_rows:
            print("  (No intelligence extracted yet)")
        else:
            for intel in intel_rows:
                print(f"\n  Session: {intel['session_id']}")
                print(f"    Bank Accounts: {intel['bank_accounts']}")
                print(f"    UPI IDs: {intel['upi_ids']}")
                print(f"    Phishing Links: {intel['phishing_links']}")
                print(f"    Phone Numbers: {intel['phone_numbers']}")
                print(f"    Keywords: {intel['suspicious_keywords']}")
                if intel['agent_notes']:
                    print(f"    Notes: {intel['agent_notes'][:80]}...")
    except sqlite3.OperationalError as e:
        print(f"  ⚠️  Table error: {e}")
    
    conn.close()

# ============================================================================
# 2. CHAT SESSIONS DB VIEWER (Archive)
# ============================================================================

def view_chat_sessions():
    """View chat_sessions.db - Archive of ALL completed sessions."""
    print_header("📦 CHAT SESSIONS DB (Archive)")
    
    if not db_exists(CHAT_SESSIONS_DB):
        print("  ⚠️  Database not found: chat_sessions.db")
        return
    
    conn = sqlite3.connect(CHAT_SESSIONS_DB)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Show sessions summary
    print_subheader("🔹 Archived Sessions")
    try:
        cursor.execute("""
            SELECT * FROM sessions ORDER BY completed_at DESC LIMIT 10
        """)
        sessions = cursor.fetchall()
        
        if not sessions:
            print("  (No archived sessions)")
        else:
            print(f"\n  {'Session ID':<40} {'Msgs':>5} {'Scam':>6} {'Completed':<20}")
            print(f"  {'-'*40} {'-'*5} {'-'*6} {'-'*20}")
            for s in sessions:
                scam = "🚨 YES" if s['is_scam'] else "  No"
                print(f"  {s['session_id']:<40} {s['total_messages']:>5} {scam:>6} {str(s['completed_at']):<20}")
    except sqlite3.OperationalError as e:
        print(f"  ⚠️  Table error: {e}")
    
    # Count stats
    print_subheader("🔹 Statistics")
    try:
        cursor.execute("SELECT COUNT(*) FROM sessions")
        total = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM sessions WHERE is_scam = 1")
        scams = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM messages")
        total_msgs = cursor.fetchone()[0]
        
        print(f"  Total Sessions: {total}")
        print(f"  Scam Sessions: {scams}")
        print(f"  Non-Scam Sessions: {total - scams}")
        print(f"  Total Messages Archived: {total_msgs}")
    except sqlite3.OperationalError as e:
        print(f"  ⚠️  Stats error: {e}")
    
    conn.close()

# ============================================================================
# 3. SCAM SESSIONS DB VIEWER
# ============================================================================

def view_scam_sessions():
    """View scam_session.db - Confirmed scam intelligence for GUVI callback."""
    print_header("🚨 SCAM SESSION DB (GUVI Callback Data)")
    
    if not db_exists(SCAM_SESSION_DB):
        print("  ⚠️  Database not found: scam_session.db")
        return
    
    conn = sqlite3.connect(SCAM_SESSION_DB)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    print_subheader("🔹 Confirmed Scam Intelligence")
    try:
        cursor.execute("""
            SELECT * FROM scam_intelligence ORDER BY created_at DESC LIMIT 10
        """)
        scams = cursor.fetchall()
        
        if not scams:
            print("  (No confirmed scams)")
        else:
            for s in scams:
                pushed = "✅ Pushed" if s['pushed_to_guvi'] else "⏳ Pending"
                print(f"\n  Session: {s['session_id']}")
                print(f"    Total Messages: {s['total_messages_exchanged']}")
                print(f"    GUVI Status: {pushed}")
                print(f"    Bank Accounts: {s['bank_accounts']}")
                print(f"    UPI IDs: {s['upi_ids']}")
                print(f"    Phishing Links: {s['phishing_links']}")
                print(f"    Phone Numbers: {s['phone_numbers']}")
                print(f"    Keywords: {s['suspicious_keywords']}")
                if s['agent_notes']:
                    print(f"    Agent Notes: {s['agent_notes'][:100]}...")
                print(f"    Created: {s['created_at']}")
    except sqlite3.OperationalError as e:
        print(f"  ⚠️  Table error: {e}")
    
    # Show GUVI payload format
    print_subheader("🔹 GUVI Payload Format (Ready to Send)")
    try:
        cursor.execute("SELECT * FROM scam_intelligence WHERE pushed_to_guvi = 0 LIMIT 1")
        pending = cursor.fetchone()
        
        if pending:
            payload = {
                "sessionId": pending['session_id'],
                "scamDetected": True,
                "totalMessagesExchanged": pending['total_messages_exchanged'],
                "extractedIntelligence": {
                    "bankAccounts": json.loads(pending['bank_accounts']),
                    "upiIds": json.loads(pending['upi_ids']),
                    "phishingLinks": json.loads(pending['phishing_links']),
                    "phoneNumbers": json.loads(pending['phone_numbers']),
                    "suspiciousKeywords": json.loads(pending['suspicious_keywords'])
                },
                "agentNotes": pending['agent_notes']
            }
            print(f"\n{json.dumps(payload, indent=2, ensure_ascii=False)}")
        else:
            print("  (No pending payloads to send)")
    except Exception as e:
        print(f"  ⚠️  Payload error: {e}")
    
    # Stats
    print_subheader("🔹 Statistics")
    try:
        cursor.execute("SELECT COUNT(*) FROM scam_intelligence")
        total = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM scam_intelligence WHERE pushed_to_guvi = 1")
        pushed = cursor.fetchone()[0]
        
        print(f"  Total Confirmed Scams: {total}")
        print(f"  Pushed to GUVI: {pushed}")
        print(f"  Pending Push: {total - pushed}")
    except sqlite3.OperationalError as e:
        print(f"  ⚠️  Stats error: {e}")
    
    conn.close()

# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="View Honeypot Scam Detection Databases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python view_db.py --current     Show active sessions
  python view_db.py --archive     Show archived sessions
  python view_db.py --scams       Show confirmed scam intelligence
  python view_db.py --all         Show all databases
        """
    )
    
    parser.add_argument('--current', '-c', action='store_true', 
                        help='Show current_session.db (active sessions)')
    parser.add_argument('--archive', '-a', action='store_true', 
                        help='Show chat_sessions.db (archived sessions)')
    parser.add_argument('--scams', '-s', action='store_true', 
                        help='Show scam_sessions.db (GUVI callback data)')
    parser.add_argument('--all', action='store_true', 
                        help='Show all databases')
    
    args = parser.parse_args()
    
    # Default to --all if no flags specified
    if not (args.current or args.archive or args.scams or args.all):
        args.all = True
    
    print("\n" + "=" * 70)
    print("  🍯 HONEYPOT SCAM DETECTION - DATABASE VIEWER")
    print("=" * 70)
    
    if args.all or args.current:
        view_current_session()
    
    if args.all or args.archive:
        view_chat_sessions()
    
    if args.all or args.scams:
        view_scam_sessions()
    
    print("\n" + "=" * 70)
    print("  Done!")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    main()

