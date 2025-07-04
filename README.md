# LogSentinel 🔍🛡️

A simple Python-based tool to detect and save suspicious system log entries, built for cybersecurity learning and basic monitoring.

---

## 🚀 Features

- Parses Linux system logs (e.g. `/var/log/auth.log`)
- Detects suspicious entries like:
  - Failed login attempts
  - Invalid users
  - Authentication failures
- Saves detected entries into an SQLite database
- Easily extendable
- Optionally serves a simple dashboard (HTML)

---

## 📁 Project Structure

```

logsentinel/
├── main.py                # Main runner script
├── parser.py              # Log parsing and detection logic
├── db.py                  # SQLite integration
├── templates/
│   └── dashboard.html     # Optional HTML dashboard
├── static/
│   └── style.css          # CSS for dashboard
└── logs/
└── sample\_auth.log    # Sample system log file

```

---

## 🧰 Requirements

- Python 3.7+
- Works on Linux (you can adapt it for Windows)

Install dependencies (currently no external ones used):

```bash
pip install -r requirements.txt
```

---

## 🛠️ Usage

1. **Clone the repository**

```bash
git clone https://github.com/pasta-lover69/LogSentinel.git
cd logsentinel
```

2. **Place a system log file in the `logs/` folder**

Example (Linux):

```bash
sudo cp /var/log/auth.log logs/sample_auth.log
```

3. **Run the program**

```bash
python main.py
```

You will see suspicious entries printed and stored in `suspicious_logs.db`.

---

## 🧪 Example Suspicious Log Detected

```
Jun 18 01:22:13 myhost sshd[1993]: Failed password for invalid user admin from 192.168.0.101 port 53742 ssh2
```

---

## 🧩 Optional Features (Planned)

- Web dashboard to view logs
- Real-time log monitoring
- Log upload interface
- Signature-based alert system
- Windows Event Log support

---

## 🤝 Contributing

Pull requests are welcome! Feel free to open issues for feature requests or bug reports.

---

## 🙋‍♂️ Author

Created by JEBSKIE WATAPAMPA UV – aspiring cybersecurity analyst.

```

Let me know if you want:
- The same for a `LICENSE` file (MIT, GPL, etc.)
- A `requirements.txt` file
- GitHub Actions CI setup
- Real-time log monitoring using `watchdog` or `inotify` tools
```
