# LogSentinel 🔍🛡️

A comprehensive Python-based security log monitoring tool with a modern web dashboard for detecting and managing suspicious system log entries. Built for cybersecurity learning, professional monitoring, and enterprise security operations with a roadmap towards AI-powered threat intelligence and global security collaboration.

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

### Real-time Monitoring 🔴

- **File Watchers**: Automatically monitors log files for new entries
- **Instant Detection**: Real-time analysis of new log entries as they're written
- **Live Alerts**: Immediate notifications when suspicious activities are detected
- **Background Processing**: Continuous monitoring without manual intervention
- **Status Tracking**: Visual indicators for monitoring state (ACTIVE/STOPPED)

### Web Dashboard 🌐

- **Modern UI**: Beautiful, responsive web interface
- **Real-time Statistics**: Live counts and detection metrics
- **Interactive Management**:
  - View all suspicious logs in a sortable table
  - Delete individual entries
  - Clear all logs with confirmation
  - One-click log scanning
  - Start/Stop real-time monitoring
- **Live Alert Feed**: Real-time display of newly detected threats
- **Smart Timestamps**: Human-readable relative time display
- **Flash Messaging**: User feedback for all actions
- **Mobile Responsive**: Works perfectly on desktop and mobile devices

---

## 📁 Project Structure

```
logsentinel/
├── main.py                # Core log scanning logic
├── app.py                 # Flask web application with real-time features
├── parser.py              # Log parsing and detection algorithms
├── db.py                  # SQLite database operations
├── monitor.py             # Real-time file monitoring system
├── migrate_db.py          # Database migration utility
├── test_realtime.py       # Real-time monitoring test script
├── requirements.txt       # Python dependencies
├── templates/
│   └── dashboard.html     # Modern web dashboard with live alerts
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
- **Watchdog 3.0.0** for real-time file monitoring
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
   - **Start Real-time Monitor** to enable continuous monitoring
   - View detected suspicious activities in real-time
   - Monitor live alert feed for instant threat detection
   - Manage and delete log entries
   - Monitor security statistics

### Option 2: Real-time Monitoring (CLI) 🔴

4. **Start real-time monitoring directly**

```bash
python monitor.py
```

5. **Test real-time detection**

```bash
# In another terminal, run the test script
python test_realtime.py
```

### Option 3: Command Line Scanner

4. **Run the command-line scanner**

```bash
python main.py
```

You will see suspicious entries printed to console and stored in `suspicious_logs.db`.

---

## 🔴 Real-time Monitoring Features

### Automatic File Watching

- **Continuous Monitoring**: Watches log files 24/7 for new entries
- **Instant Processing**: Analyzes new log lines immediately as they're written
- **Smart Positioning**: Tracks file positions to avoid re-processing existing content
- **File Rotation Support**: Handles log file rotation and new file creation

### Live Alert System

- **Real-time Notifications**: Instant alerts when suspicious activities are detected
- **Alert History**: Recent alerts displayed in the dashboard
- **Background Processing**: Works silently in the background
- **Zero Configuration**: Automatically starts monitoring when dashboard launches

### Monitoring Controls

- **Start/Stop Controls**: Easy toggle buttons in web dashboard
- **Status Indicators**: Visual display of monitoring state (ACTIVE/STOPPED)
- **File Status**: Shows which files are being monitored
- **Position Tracking**: Displays current monitoring positions for each file

---

## 🎯 Dashboard Features

### Statistics Dashboard

- **Total Suspicious Logs**: Real-time count of all detected threats
- **Currently Displayed**: Number of logs shown in current view
- **Last Detection**: Smart timestamp showing when the most recent threat was detected
- **Monitor Status**: Live indicator showing real-time monitoring state

### Real-time Alert Feed 🚨

- **Live Alerts**: Recent suspicious activities detected in real-time
- **Instant Updates**: New threats appear immediately without page refresh
- **Alert Management**: Clear recent alerts with one click
- **Timestamp Display**: Shows exactly when each threat was detected

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

**Core Dashboard:**

- `GET /` - Main dashboard with real-time status
- `GET /scan` - Trigger log scan
- `GET /delete/<id>` - Delete specific log entry
- `POST /clear_all` - Clear all logs

**Real-time Monitoring:**

- `GET /monitoring/start` - Start real-time monitoring
- `GET /monitoring/stop` - Stop real-time monitoring
- `GET /monitoring/status` - Get monitoring status (JSON)
- `GET /api/alerts` - Get recent alerts (JSON)
- `POST /clear_alerts` - Clear recent alerts

### Testing Real-time Monitoring

Use the included test script to simulate suspicious log entries:

```bash
# Start the web dashboard first
python app.py

# In another terminal, run the test
python test_realtime.py
```

Watch the dashboard for real-time alerts as the test script adds suspicious entries!

---

## 🧩 Feature Status

- ✅ ~~Web dashboard to view logs~~ **COMPLETED**
- ✅ ~~Real-time statistics~~ **COMPLETED**
- ✅ ~~Interactive log management~~ **COMPLETED**
- ✅ ~~Real-time log monitoring with file watchers~~ **COMPLETED**
- 🔄 Log upload interface for remote files
- 🔄 Email/Slack alert notifications
- 🔄 Advanced pattern matching with regex builder
- 🔄 Windows Event Log support
- 🔄 Multi-file monitoring dashboard
- 🔄 User authentication and role management

---

## 🗺️ Future Enhancement Roadmap

### **Phase 1: Essential Enterprise Features (Short-term)**

#### **🔔 Notification System**
- **Email Alerts**: Configurable email notifications for critical threats
- **Slack Integration**: Real-time alerts to security team channels
- **Discord Webhooks**: Community-friendly notification support
- **SMS Alerts**: Critical incident notifications via text message
- **Webhook Support**: Generic webhook endpoints for SIEM integration

#### **🏢 Multi-Platform Support**
- **Windows Event Logs**: Complete Windows environment monitoring
- **Docker Container Logs**: Cloud-native application security
- **Custom Log Formats**: User-defined parsing patterns
- **Cloud Log Integration**: AWS CloudTrail, Azure Activity Logs

#### **🎯 Custom Rule Builder**
- **GUI Rule Creator**: Visual interface for detection patterns
- **Regex Pattern Builder**: Advanced pattern matching without coding
- **Threat Severity Scoring**: Automated risk assessment
- **Custom Alert Templates**: Personalized notification formats

### **Phase 2: Advanced Analytics & Intelligence (Medium-term)**

#### **🧠 AI-Powered Detection**
- **Machine Learning Models**: Anomaly detection beyond simple rules
- **Behavioral Analysis**: User behavior pattern recognition
- **Predictive Analytics**: Forecast potential security incidents
- **Natural Language Queries**: "Show me failed logins from suspicious IPs"

#### **📊 Advanced Analytics Dashboard**
- **Attack Timeline Visualization**: Interactive incident progression
- **Threat Hunting Interface**: Advanced search and correlation tools
- **Executive Reporting**: Automated PDF reports for management
- **Compliance Templates**: SOC2, PCI-DSS, GDPR reporting modules

#### **🌐 Threat Intelligence Integration**
- **VirusTotal API**: Automated IP/domain reputation checking
- **MISP Platform**: Threat intelligence sharing and correlation
- **Geolocation Services**: Geographic threat analysis
- **IOC Database**: Indicators of Compromise management

### **Phase 3: Enterprise & Cloud Architecture (Long-term)**

#### **🔐 Enterprise Security Features**
- **Multi-tenant Architecture**: Organization isolation and management
- **Role-Based Access Control**: Admin, analyst, viewer, and custom roles
- **Single Sign-On (SSO)**: SAML, OAuth2, Active Directory integration
- **Audit Logging**: Complete activity tracking and compliance
- **Data Encryption**: End-to-end encryption for sensitive log data

#### **☁️ Cloud-Native Deployment**
- **PostgreSQL Migration**: Scalable database architecture
- **Docker Containerization**: Easy deployment and scaling
- **Kubernetes Support**: Orchestration and auto-scaling
- **Multi-cloud Support**: AWS, Azure, GCP deployment options
- **CDN Integration**: Global performance optimization

#### **📱 Modern User Experience**
- **Mobile Application**: iOS/Android apps for security teams
- **Dark Mode Interface**: Professional security analyst theme
- **Customizable Dashboards**: Drag-and-drop widget system
- **Keyboard Shortcuts**: Power user efficiency features
- **Real-time Collaboration**: Team-based threat investigation

#### **⚡ Performance & Scalability**
- **Apache Kafka Integration**: High-volume log streaming
- **Redis Caching**: Ultra-fast query performance
- **Load Balancing**: Multi-instance deployment support
- **Background Processing**: Celery-based task management
- **Auto-scaling**: Dynamic resource allocation

### **Phase 4: AI & Automation Revolution (Future Vision)**

#### **🤖 Intelligent Automation**
- **Automated Incident Response**: Smart threat mitigation
- **AI Chatbot Assistant**: Natural language log analysis
- **Self-Learning Rules**: Adaptive detection patterns
- **Risk Prediction Models**: Proactive security posturing
- **Automated Compliance**: Self-auditing and reporting

#### **🌍 Global Security Platform**
- **Threat Intelligence Sharing**: Community-driven security data
- **Global Threat Map**: Real-time worldwide attack visualization
- **Collaborative Defense**: Shared protection mechanisms
- **Open Source Ecosystem**: Plugin and extension marketplace

---

## 🎯 Development Priorities

### **Immediate Goals (Next 3 months)**
1. **Email Notification System** - Most requested production feature
2. **Windows Event Log Support** - Expand platform compatibility  
3. **Custom Rule Builder** - Make accessible to non-programmers
4. **PostgreSQL Migration** - Essential for scalability

### **Short-term Goals (3-6 months)**
5. **User Authentication & RBAC** - Enterprise readiness
6. **Advanced Analytics Dashboard** - Enhanced threat visualization
7. **Slack/Discord Integration** - Team collaboration features
8. **Docker Deployment** - Easy installation and scaling

### **Medium-term Vision (6-12 months)**
9. **Machine Learning Integration** - Intelligent threat detection
10. **Mobile Application** - On-the-go security monitoring
11. **Cloud Deployment Architecture** - Global accessibility
12. **Threat Intelligence Platform** - Enhanced detection capabilities

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
2. Check that Flask and Watchdog are properly installed: `pip list | grep -E "(Flask|watchdog)"`
3. Verify log file exists in `logs/` directory
4. Make sure port 5000 is available

### Common Issues

- **Database errors**: Run `python migrate_db.py` to fix schema issues
- **Port conflicts**: Change port in `app.py` if 5000 is in use
- **Permission errors**: Ensure read access to log files
- **Real-time monitoring not working**: Check that `watchdog` is installed and log files are in the `logs/` directory
- **Threading errors**: Real-time monitoring may conflict with Flask debug mode on some systems

### Real-time Monitoring Troubleshooting

- **Monitor shows "STOPPED"**: Click "Start Real-time Monitor" in the dashboard
- **No real-time alerts**: Ensure log files are being written to the `logs/` directory
- **Test monitoring**: Use `python test_realtime.py` to simulate suspicious entries
- **Check status**: Visit `/monitoring/status` endpoint for detailed monitoring information

### Support

- 📖 Check the [Issues](https://github.com/pasta-lover69/LogSentinel/issues) page
- 💬 Open a new issue for bugs or questions
- 📧 Contact the author for security-related concerns

---

*LogSentinel - Your intelligent guardian evolving from real-time monitoring to AI-powered global security intelligence* 🛡️✨🔴🚀
