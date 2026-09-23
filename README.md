# Cloud Log Analytics System

A real-time log analytics and monitoring dashboard with ML anomaly detection.

## Features
- Real-time log generation and processing
- ML-based anomaly detection (Isolation Forest)
- Predictive analytics (6-hour error forecast)
- User authentication with role-based access
- Interactive dashboard with charts and geographic distribution

## Project Structure
```
log-analytics-system/
├── main.py              # Main application entry point
├── requirements.txt     # Python dependencies
├── frontend/
│   ├── index.html       # Dashboard UI
│   └── login.html       # Login page
├── logs.db              # SQLite database (auto-created)
├── .gitignore
└── README.md
```

## Setup & Run

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

Open browser: http://localhost:5000

## Login Credentials
| Role   | Username | Password   |
|--------|----------|------------|
| Admin  | admin    | admin123   |
| Viewer | viewer   | viewer123  |

## Tech Stack
- Backend: Python, Flask, SQLite
- ML: scikit-learn (Isolation Forest)
- Frontend: HTML, Bootstrap 5, Chart.js
