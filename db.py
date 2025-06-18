import sqlite3

DB_NAME = "suspicious_logs.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    log TEXT
                )''')
    conn.commit()
    conn.close()

def save_suspicious_log(log_entry):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO logs (log) VALUES (?)", (log_entry,))
    conn.commit()
    conn.close()
