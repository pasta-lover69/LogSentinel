import re

def parse_logs(log_file):
    suspicious = []
    with open(log_file, 'r') as f:
        for line in f:
            if is_suspicious(line):
                suspicious.append(line.strip())
    return suspicious

def is_suspicious(line):
    # Simple example: detect failed login attempts
    return ("Failed password" in line or 
            "authentication failure" in line or
            re.search(r'Invalid user', line))
