import sqlite3
import os
import random
import time
import threading
import hashlib
import statistics
from datetime import datetime, timedelta
from queue import Queue
from flask import Flask, jsonify, request, session, send_from_directory
from flask_cors import CORS
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd

DB_PATH = 'logs.db'
LOG_QUEUE = Queue(maxsize=10000)
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')
CORS(app, supports_credentials=True, origins=['http://localhost:5000'])

ml_model = None
scaler = StandardScaler()

# ── Database ──────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, log_level TEXT, message TEXT,
        source TEXT, user_id TEXT, ip_address TEXT,
        response_time INTEGER, status_code INTEGER,
        endpoint TEXT, country TEXT,
        is_anomaly INTEGER DEFAULT 0, anomaly_score REAL DEFAULT 0
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_type TEXT, severity TEXT, message TEXT, triggered_at TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS auth_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE, password_hash TEXT, role TEXT
    )''')
    for u, p, r in [('admin','admin123','admin'), ('viewer','viewer123','viewer')]:
        try:
            c.execute('INSERT INTO auth_users (username,password_hash,role) VALUES (?,?,?)',
                      (u, hashlib.sha256(p.encode()).hexdigest(), r))
        except: pass
    conn.commit()
    conn.close()

# ── ML ────────────────────────────────────────────────────────────────────────
def train_ml_model():
    global ml_model, scaler
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql('SELECT response_time, status_code FROM logs LIMIT 1000', conn)
    conn.close()
    if len(df) < 100: return
    features = scaler.fit_transform(df[['response_time','status_code']].values)
    ml_model = IsolationForest(contamination=0.1, random_state=42)
    ml_model.fit(features)

def detect_anomaly(log):
    if ml_model is None: return 0, 0.0
    try:
        f = scaler.transform([[log['response_time'], log['status_code']]])
        pred = ml_model.predict(f)[0]
        score = abs(ml_model.score_samples(f)[0])
        return (1 if pred == -1 else 0), score
    except: return 0, 0.0

# ── Log Generator ─────────────────────────────────────────────────────────────
LEVELS   = ['INFO','WARNING','ERROR','DEBUG','CRITICAL']
SOURCES  = ['web-server','api-gateway','database','auth-service','payment-service']
USERS    = [f'user_{i}' for i in range(1, 51)]
COUNTRIES= ['USA','UK','India','Germany','France','Japan','Canada','Australia']
MSGS = {
    'INFO':     ['User logged in','Request processed','Cache updated'],
    'WARNING':  ['High memory usage','Slow query detected'],
    'ERROR':    ['Database connection failed','Authentication failed'],
    'DEBUG':    ['Processing request','Query executed'],
    'CRITICAL': ['System overload','Database crash']
}

def generate_log():
    level = random.choices(LEVELS, weights=[50,20,15,10,5])[0]
    return {
        'timestamp':     datetime.now().isoformat(),
        'log_level':     level,
        'message':       random.choice(MSGS[level]),
        'source':        random.choice(SOURCES),
        'user_id':       random.choice(USERS),
        'ip_address':    f'192.168.{random.randint(1,255)}.{random.randint(1,255)}',
        'response_time': random.randint(50, 3000),
        'status_code':   random.choice([200,200,200,201,400,404,500]),
        'endpoint':      random.choice(['/api/users','/api/products','/api/orders']),
        'country':       random.choice(COUNTRIES)
    }

def log_producer():
    while True:
        LOG_QUEUE.put(generate_log())
        time.sleep(random.uniform(0.1, 0.5))

def process_logs():
    batch = []
    while True:
        try:
            log = LOG_QUEUE.get(timeout=1)
            log['is_anomaly'], log['anomaly_score'] = detect_anomaly(log)
            batch.append(log)
            if len(batch) >= 10:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                for l in batch:
                    c.execute('''INSERT INTO logs (timestamp,log_level,message,source,user_id,
                                 ip_address,response_time,status_code,endpoint,country,is_anomaly,anomaly_score)
                                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                              (l['timestamp'],l['log_level'],l['message'],l['source'],l['user_id'],
                               l['ip_address'],l['response_time'],l['status_code'],l['endpoint'],
                               l['country'],l['is_anomaly'],l['anomaly_score']))
                conn.commit()
                conn.close()
                batch = []
        except: pass

def ml_trainer():
    while True:
        time.sleep(60)
        try: train_ml_model()
        except: pass

# ── Auth helper ───────────────────────────────────────────────────────────────
def is_logged_in():
    return 'user_id' in session

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    if is_logged_in():
        return send_from_directory('frontend', 'index.html')
    return send_from_directory('frontend', 'login.html')

@app.route('/login')
def login_page():
    return send_from_directory('frontend', 'login.html')

@app.route('/dashboard')
def dashboard():
    return send_from_directory('frontend', 'index.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username','')
    password = data.get('password','')
    pw_hash  = hashlib.sha256(password.encode()).hexdigest()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM auth_users WHERE username=? AND password_hash=?', (username, pw_hash))
    user = c.fetchone()
    conn.close()

    if user:
        session.permanent = True
        session['user_id']  = user['id']
        session['username'] = user['username']
        session['role']     = user['role']
        return jsonify({'success': True, 'username': user['username'], 'role': user['role']})
    return jsonify({'success': False, 'message': 'Invalid username or password'}), 401

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/me')
def api_me():
    if not is_logged_in():
        return jsonify({'success': False}), 401
    return jsonify({'success': True, 'username': session['username'], 'role': session['role']})

@app.route('/api/logs')
def api_logs():
    if not is_logged_in():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    level = request.args.get('level')
    if level:
        c.execute('SELECT * FROM logs WHERE log_level=? ORDER BY timestamp DESC LIMIT 50', (level,))
    else:
        c.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 50')
    logs = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify({'success': True, 'data': logs})

@app.route('/api/metrics')
def api_metrics():
    if not is_logged_in():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute('SELECT COUNT(*) as n FROM logs')
    total = c.fetchone()['n']

    c.execute("SELECT COUNT(*) as n FROM logs WHERE log_level IN ('ERROR','CRITICAL')")
    errors = c.fetchone()['n']

    c.execute('SELECT log_level, COUNT(*) as count FROM logs GROUP BY log_level')
    by_level = [dict(r) for r in c.fetchall()]

    c.execute("""SELECT strftime('%H:%M', timestamp) as t, COUNT(*) as count
                 FROM logs WHERE timestamp >= datetime('now','-1 hour')
                 GROUP BY t ORDER BY t""")
    activity = [dict(r) for r in c.fetchall()]

    c.execute('SELECT source, COUNT(*) as count FROM logs GROUP BY source ORDER BY count DESC LIMIT 5')
    sources = [dict(r) for r in c.fetchall()]

    c.execute('SELECT AVG(response_time) as avg FROM logs')
    avg_rt = int(c.fetchone()['avg'] or 0)

    c.execute('SELECT country, COUNT(*) as count FROM logs GROUP BY country ORDER BY count DESC')
    geo = [dict(r) for r in c.fetchall()]

    c.execute('SELECT COUNT(DISTINCT user_id) as n FROM logs')
    users = c.fetchone()['n']

    c.execute('SELECT COUNT(*) as n FROM logs WHERE is_anomaly=1')
    anomalies = c.fetchone()['n']

    # Predictive analytics - next 6 hours forecast
    c.execute("""SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hr, COUNT(*) as cnt
                 FROM logs WHERE log_level IN ('ERROR','CRITICAL')
                 AND timestamp >= datetime('now','-24 hours')
                 GROUP BY hr ORDER BY hr""")
    err_rows = c.fetchall()
    predictions = []
    if len(err_rows) >= 3:
        vals = [r['cnt'] for r in err_rows]
        avg_err = sum(vals[-3:]) / 3
        for i in range(1, 7):
            predictions.append({
                'hour': (datetime.now() + timedelta(hours=i)).strftime('%H:00'),
                'predicted': round(avg_err, 1),
                'lower': round(avg_err * 0.8, 1),
                'upper': round(avg_err * 1.2, 1)
            })

    conn.close()
    health = max(0, min(100, 100 - (errors / max(total, 1)) * 100))
    return jsonify({'success': True, 'data': {
        'total_logs': total, 'error_count': errors,
        'logs_by_level': by_level, 'recent_activity': activity,
        'top_sources': sources, 'avg_response_time': avg_rt,
        'geographic_data': geo, 'active_users': users,
        'system_health': round(health, 1),
        'anomaly_count': anomalies, 'predictions': predictions
    }})

@app.route('/api/alerts')
def api_alerts():
    if not is_logged_in():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM alerts ORDER BY triggered_at DESC LIMIT 20')
    alerts = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify({'success': True, 'data': alerts})

@app.route('/api/anomalies')
def api_anomalies():
    if not is_logged_in():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM logs WHERE is_anomaly=1 ORDER BY timestamp DESC LIMIT 50')
    data = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify({'success': True, 'data': data})

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("=" * 60)
    print("  Log Analytics System")
    print("=" * 60)
    init_db()
    print("[OK] Database ready")
    threading.Thread(target=log_producer, daemon=True).start()
    print("[OK] Log producer started")
    threading.Thread(target=process_logs, daemon=True).start()
    print("[OK] Log processor started")
    threading.Thread(target=ml_trainer, daemon=True).start()
    print("[OK] ML trainer started")
    print("\n  URL  : http://localhost:5000")
    print("  Login: admin / admin123")
    print("         viewer / viewer123")
    print("\n  Press Ctrl+C to stop")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
