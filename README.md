# LogSentinel 🔍🛡️

A comprehensive Python-based security log monitoring tool with a modern web dashboard for detecting and managing suspicious system log entries, built for cybersecurity learning and professional monitoring.

---

## 🚀 Features

### Core Functionality

- **Smart Log Parsing**: Analyzes Linux system logs (e.g. `/var/log/auth.log`)
- **Advanced Detection**: Identifies suspicious activities including:
  - Failed login attempts
  - Invalid user access attempts
  - Authentication failures
  - Customizable detection patterns
- **Persistent Storage**: SQLite database with timestamp tracking
- **Extensible Architecture**: Easy to add new detection rules

### Web Dashboard 🌐

- **Modern UI**: Beautiful, responsive web interface
- **Real-time Statistics**: Live counts and detection metrics
- **Interactive Management**:
  - View all suspicious logs in a sortable table
  - Delete individual entries
  - Clear all logs with confirmation
  - One-click log scanning
- **Smart Timestamps**: Human-readable relative time display
- **Flash Messaging**: User feedback for all actions
- **Mobile Responsive**: Works perfectly on desktop and mobile devices

---

## 📁 Project Structure

```
logsentinel/
├── main.py                # Core log scanning logic
├── app.py                 # Flask web application
├── parser.py              # Log parsing and detection algorithms
├── db.py                  # SQLite database operations
├── migrate_db.py          # Database migration utility
├── requirements.txt       # Python dependencies
├── templates/
│   └── dashboard.html     # Modern web dashboard
├── static/
│   └── style.css          # Beautiful CSS styling
├── logs/
│   └── sample_auth.log    # Sample system log file
└── suspicious_logs.db     # SQLite database (auto-created)
```

---

## 🧰 Requirements

- **Python 3.7+** (tested on Python 3.13)
- **Flask 2.3.3** for web dashboard
- **SQLite** (built into Python)
- **Modern web browser** for dashboard access

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 🛠️ Usage

### Quick Start

1. **Clone the repository**

```bash
git clone https://github.com/pasta-lover69/LogSentinel.git
cd LogSentinel
```

2. **Install dependencies**

```bash
pip install -r requirements.txt
```

3. **Place a system log file in the `logs/` folder**

Example (Linux):

```bash
sudo cp /var/log/auth.log logs/sample_auth.log
```

### Option 1: Web Dashboard (Recommended) 🌐

4. **Start the web dashboard**

```bash
python app.py
```

5. **Open your browser and visit**

```
http://127.0.0.1:5000
```

6. **Use the dashboard to:**
   - Click "Scan Logs" to analyze your log files
   - View detected suspicious activities in real-time
   - Manage and delete log entries
   - Monitor security statistics

### Option 2: Command Line

4. **Run the command-line scanner**

```bash
python main.py
```

You will see suspicious entries printed to console and stored in `suspicious_logs.db`.

---

## 🎯 Dashboard Features

### Statistics Dashboard

- **Total Suspicious Logs**: Real-time count of all detected threats
- **Currently Displayed**: Number of logs shown in current view
- **Last Detection**: Smart timestamp showing when the most recent threat was detected

### Interactive Log Management

- **Sortable Table**: View all logs with ID, content, and timestamp
- **Smart Timestamps**: Human-readable time display (e.g., "2 hours ago", "Yesterday")
- **Individual Actions**: Delete specific log entries with confirmation
- **Bulk Operations**: Clear all logs with safety confirmation
- **One-Click Scanning**: Rescan log files for new threats

### Modern UI Elements

- **Responsive Design**: Works on desktop, tablet, and mobile
- **Flash Messages**: Clear feedback for all user actions
- **Beautiful Styling**: Modern gradient design with smooth animations
- **Font Awesome Icons**: Professional iconography throughout
- **Empty States**: Helpful guidance when no logs are detected

---

## 🧪 Example Suspicious Logs Detected

```
Jun 18 01:22:13 myhost sshd[1993]: Failed password for invalid user admin from 192.168.0.101 port 53742 ssh2
Jun 18 01:22:15 myhost sshd[1993]: Failed password for root from 192.168.0.102 port 53743 ssh2
Jun 18 01:22:17 myhost sshd[1994]: Invalid user test from 192.168.0.103
```

These entries indicate potential brute-force attacks or unauthorized access attempts, which LogSentinel automatically detects and stores for analysis.

---

## 🔧 Configuration & Customization

### Adding Custom Detection Rules

Edit `parser.py` to add new suspicious patterns:

```python
def is_suspicious(line):
    # Add your custom detection logic
    return ("Failed password" in line or
            "authentication failure" in line or
            "Invalid user" in line or
            "YOUR_CUSTOM_PATTERN" in line)
```

### Database Schema

The SQLite database includes:

- `id`: Unique identifier for each log entry
- `log`: The complete suspicious log entry
- `timestamp`: When the log was detected (ISO format)

### Web Dashboard Customization

- **Styling**: Modify `static/style.css` for custom themes
- **Templates**: Edit `templates/dashboard.html` for layout changes
- **Functionality**: Extend `app.py` for additional features

---

## 🚀 Advanced Features

### Database Migration

If you upgrade from an older version, run the migration script:

```bash
python migrate_db.py
```

### API Endpoints

The web dashboard provides several endpoints:

- `GET /` - Main dashboard
- `GET /scan` - Trigger log scan
- `GET /delete/<id>` - Delete specific log entry
- `POST /clear_all` - Clear all logs

---

## 🧩 Planned Features

- ✅ ~~Web dashboard to view logs~~ **COMPLETED**
- ✅ ~~Real-time statistics~~ **COMPLETED**
- ✅ ~~Interactive log management~~ **COMPLETED**
- 🔄 Real-time log monitoring with file watchers
- 🔄 Log upload interface for remote files
- 🔄 Email/Slack alert notifications
- 🔄 Advanced pattern matching with regex builder
- 🔄 Windows Event Log support
- 🔄 Multi-file monitoring
- 🔄 User authentication and role management

---

## 📸 Screenshots

### Main Dashboard

![Dashboard showing suspicious log statistics and management interface]

### Log Table View

![Interactive table with human-readable timestamps and delete actions]

### Empty State

![Clean interface when no suspicious logs are detected]

_Screenshots show the modern, responsive web interface with real-time statistics and interactive log management._

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Quick Contributions

- 🐛 **Bug Reports**: Open an issue with detailed reproduction steps
- 💡 **Feature Requests**: Suggest new detection patterns or dashboard features
- 📖 **Documentation**: Improve README, add code comments

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and test thoroughly
4. Ensure the web dashboard works properly
5. Submit a pull request with clear description

### Areas for Contribution

- New suspicious log patterns
- Additional database backends
- Mobile app companion
- API integrations
- Performance optimizations

---

## 📝 License

This project is open source and available under the [MIT License](LICENSE).

---

## 🙋‍♂️ Author

**JEBSKIE WATAPAMPA UV** – Aspiring Cybersecurity Analyst  
🔗 [GitHub](https://github.com/pasta-lover69) | 📧 [Contact](mailto:your-email@example.com)

Built with ❤️ for the cybersecurity community and security enthusiasts worldwide.

---

## 🚨 Security Notice

LogSentinel is designed for educational purposes and legitimate security monitoring. Always ensure you have proper authorization before monitoring log files in production environments. Follow your organization's security policies and local regulations.

---

## 💡 Getting Help

### Quick Start Issues?

1. Ensure Python 3.7+ is installed
2. Check that Flask is properly installed: `pip list | grep Flask`
3. Verify log file exists in `logs/` directory
4. Make sure port 5000 is available

### Common Issues

- **Database errors**: Run `python migrate_db.py` to fix schema issues
- **Port conflicts**: Change port in `app.py` if 5000 is in use
- **Permission errors**: Ensure read access to log files

### Support

- 📖 Check the [Issues](https://github.com/pasta-lover69/LogSentinel/issues) page
- 💬 Open a new issue for bugs or questions
- 📧 Contact the author for security-related concerns

---

_LogSentinel - Your vigilant guardian against suspicious activities_ 🛡️✨
