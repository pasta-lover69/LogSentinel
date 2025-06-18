from parser import parse_logs
from db import init_db, save_suspicious_log

LOG_FILE= "logs/sample_auth.log"

def main():
    init_db()
    suspicious_entries = parse_logs(LOG_FILE)
    for entry in suspicious_entries:
        print("[!] That's SUS: ", entry)
        save_suspicious_log(entry)

if __name__ == "__main__":
    main()