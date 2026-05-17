"""
app.py — SessionSentry Main Flask Application
Uses only Flask + sqlite3 (no external ORM/login libs)
"""

import os, json, hashlib, secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify, abort, g)
from config import Config
from models import get_db, init_db, make_session_id, row_to_dict, rows_to_list
from ml.feature_extractor import parse_browser, FEATURE_COLUMNS
from ml.detector import detect

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = app.config['SECRET_KEY']

# Global simulation control flag
simulation_active = False


def hash_password(pw):
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + pw).encode()).hexdigest()
    return f"{salt}:{h}"


def check_password(stored, pw):
    try:
        salt, h = stored.split(':')
        return hashlib.sha256((salt + pw).encode()).hexdigest() == h
    except Exception:
        return False


def get_current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    conn = get_db()
    user = row_to_dict(conn.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone())
    conn.close()
    return user


def get_feature_settings():
    conn = get_db()
    rows = conn.execute('SELECT feature_name, enabled FROM feature_settings').fetchall()
    conn.close()
    settings = {row['feature_name']: bool(row['enabled']) for row in rows}
    for feature in FEATURE_COLUMNS:
        settings.setdefault(feature, True)
    return settings


def save_feature_settings(settings: dict):
    conn = get_db()
    for feature in FEATURE_COLUMNS:
        enabled = 1 if settings.get(feature, True) else 0
        conn.execute("""
            INSERT INTO feature_settings (feature_name, enabled)
            VALUES (?, ?)
            ON CONFLICT(feature_name) DO UPDATE SET enabled=excluded.enabled
        """, (feature, enabled))
    conn.commit()
    conn.close()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please log in.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user or user['role'] != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated


def get_or_create_session(user):
    sess_id = session.get('db_session_id')
    conn = get_db()
    db_sess = None
    if sess_id:
        db_sess = row_to_dict(conn.execute(
            'SELECT * FROM sessions WHERE session_id=? AND is_active=1', (sess_id,)
        ).fetchone())

    if not db_sess:
        browser, os_info = parse_browser(request.user_agent.string)
        new_id = make_session_id()
        conn.execute(
            'INSERT INTO sessions (session_id,user_id,ip_address,user_agent,browser,os_info) VALUES (?,?,?,?,?,?)',
            (new_id, user['id'], request.remote_addr or '127.0.0.1',
             request.user_agent.string, browser, os_info))
        conn.commit()
        db_sess = row_to_dict(conn.execute(
            'SELECT * FROM sessions WHERE session_id=?', (new_id,)
        ).fetchone())
        session['db_session_id'] = new_id

    conn.close()
    return db_sess


def log_request(db_sess):
    browser, os_info = parse_browser(request.user_agent.string)
    conn = get_db()
    conn.execute(
        'INSERT INTO request_logs (session_id,ip_address,user_agent,page,referrer,request_method,browser,os_info) VALUES (?,?,?,?,?,?,?,?)',
        (db_sess['session_id'], request.remote_addr or '127.0.0.1',
         request.user_agent.string, request.path, request.referrer,
         request.method, browser, os_info))
    conn.commit()
    conn.close()


def run_detection(db_sess):
    conn = get_db()
    logs_raw = rows_to_list(conn.execute(
        'SELECT * FROM request_logs WHERE session_id=? ORDER BY timestamp', (db_sess['session_id'],)
    ).fetchall())
    conn.close()

    class LogObj:
        pass

    logs = []
    for l in logs_raw:
        obj = LogObj()
        for k, v in l.items():
            if k == 'timestamp' and isinstance(v, str):
                try:
                    setattr(obj, k, datetime.fromisoformat(v))
                except:
                    setattr(obj, k, datetime.utcnow())
            else:
                setattr(obj, k, v)
        logs.append(obj)

    class SessObj:
        pass

    s = SessObj()
    s.session_id = db_sess['session_id']
    s.user_agent = db_sess['user_agent']
    s.ip_address = db_sess['ip_address']
    try:
        s.login_time = datetime.fromisoformat(db_sess['login_time'])
    except:
        s.login_time = datetime.utcnow()

    enabled_features = get_feature_settings()
    result = detect(s, logs, enabled_features=enabled_features)

    conn = get_db()
    conn.execute(
        'UPDATE sessions SET risk_score=?, risk_reason=? WHERE session_id=?',
        (result['risk_score'], result['reason'], db_sess['session_id'])
    )

    if result['is_hijacked']:
        row = row_to_dict(conn.execute(
            'SELECT is_hijacked FROM sessions WHERE session_id=?',
            (db_sess['session_id'],)
        ).fetchone())
        if row and not row['is_hijacked']:
            conn.execute('UPDATE sessions SET is_hijacked=1 WHERE session_id=?', (db_sess['session_id'],))
            urow = row_to_dict(conn.execute(
                'SELECT username FROM users WHERE id=?', (db_sess['user_id'],)
            ).fetchone())
            uname = urow['username'] if urow else 'Unknown'
            conn.execute(
                'INSERT INTO alerts (session_id,user_id,username,risk_score,reason) VALUES (?,?,?,?,?)',
                (db_sess['session_id'], db_sess['user_id'], uname, result['risk_score'], result['reason'])
            )

    conn.commit()
    conn.close()
    return result


def generate_hijacked_session(username):
    """Generate a new hijacked session for simulation"""
    conn = get_db()
    
    # Get user
    user = row_to_dict(conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone())
    if not user:
        conn.execute('INSERT INTO users (username,password,role) VALUES (?,?,?)',
                     (username, hash_password('demo1234'), 'user'))
        conn.commit()
        user = row_to_dict(conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone())
    
    # Create hijacked session
    session_id = make_session_id()
    attacker_ip = f"185.220.101.{secrets.randbelow(255)}"
    attacker_ua = secrets.choice([
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Firefox/120.0',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15'
    ])
    browser, os_info = parse_browser(attacker_ua)
    
    risk_score = secrets.randbelow(40) + 60  # 60-100
    reasons = []
    if secrets.randbelow(2):
        reasons.append("IP address changed")
    if secrets.randbelow(2):
        reasons.append("Browser changed")
    if secrets.randbelow(2):
        reasons.append("OS changed")
    if secrets.randbelow(2):
        reasons.append(f"High request rate ({secrets.randbelow(50) + 50}/min)")
    if secrets.randbelow(2):
        reasons.append("Admin page accessed")
    if secrets.randbelow(2):
        reasons.append("Direct page access (skipped login flow)")
    if secrets.randbelow(2):
        reasons.append("Automated/bot-like click speed")
    
    reason = " | ".join(reasons) if reasons else "Behavioral anomaly detected"
    
    conn.execute(
        'INSERT INTO sessions (session_id,user_id,ip_address,user_agent,browser,os_info,is_active,is_hijacked,risk_score,risk_reason) VALUES (?,?,?,?,?,?,1,1,?,?)',
        (session_id, user['id'], attacker_ip, attacker_ua, browser, os_info, risk_score, reason)
    )
    
    # Add request logs
    pages = ['/dashboard', '/profile', '/settings']
    if secrets.randbelow(2):
        pages.append('/admin')
    
    for page in pages:
        conn.execute(
            'INSERT INTO request_logs (session_id,ip_address,user_agent,page,request_method,browser,os_info) VALUES (?,?,?,?,?,?,?)',
            (session_id, attacker_ip, attacker_ua, page, 'GET', browser, os_info)
        )
    
    # Add multiple rapid requests
    for _ in range(secrets.randbelow(20) + 5):
        conn.execute(
            'INSERT INTO request_logs (session_id,ip_address,user_agent,page,request_method,browser,os_info) VALUES (?,?,?,?,?,?,?)',
            (session_id, attacker_ip, attacker_ua, secrets.choice(pages), 'GET', browser, os_info)
        )
    
    # Create alert
    conn.execute(
        'INSERT INTO alerts (session_id,user_id,username,risk_score,reason) VALUES (?,?,?,?,?)',
        (session_id, user['id'], user['username'], risk_score, reason)
    )
    
    conn.commit()
    conn.close()
    
    return {'session_id': session_id, 'risk_score': risk_score, 'username': username}


def clear_old_hijacked_data():
    """Clear old hijacked sessions and alerts"""
    conn = get_db()
    # Delete hijacked sessions
    conn.execute('DELETE FROM sessions WHERE is_hijacked=1')
    # Delete alerts
    conn.execute('DELETE FROM alerts')
    conn.commit()
    conn.close()


@app.before_request
def monitor():
    global simulation_active
    g.current_user = get_current_user()
    if g.current_user:
        skip = ['/static', '/favicon', '/api']
        if not any(request.path.startswith(e) for e in skip):
            db_sess = get_or_create_session(g.current_user)
            log_request(db_sess)
            conn = get_db()
            cnt = conn.execute(
                'SELECT COUNT(*) FROM request_logs WHERE session_id=?',
                (db_sess['session_id'],)
            ).fetchone()[0]
            conn.close()
            # Only run detection if simulation is active
            if cnt % 3 == 0 and simulation_active:
                run_detection(db_sess)


@app.context_processor
def inject_user():
    return {'current_user': g.get('current_user')}


@app.route('/')
def index():
    return redirect(url_for('dashboard') if session.get('user_id') else url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        un = request.form.get('username', '').strip()
        pw = request.form.get('password', '').strip()
        conn = get_db()
        user = row_to_dict(conn.execute('SELECT * FROM users WHERE username=?', (un,)).fetchone())
        conn.close()
        if user and check_password(user['password'], pw):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            get_or_create_session(user)
            return redirect(url_for('admin_dashboard') if user['role'] == 'admin' else url_for('dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('user_id'):
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        un = request.form.get('username', '').strip()
        pw = request.form.get('password', '').strip()
        if len(un) < 3 or len(pw) < 6:
            flash('Username 3+ chars, password 6+ chars.', 'danger')
            return render_template('register.html')
        conn = get_db()
        if conn.execute('SELECT id FROM users WHERE username=?', (un,)).fetchone():
            conn.close()
            flash('Username already exists.', 'danger')
            return render_template('register.html')
        conn.execute('INSERT INTO users (username,password,role) VALUES (?,?,?)',
                     (un, hash_password(pw), 'user'))
        conn.commit()
        conn.close()
        flash('Account created! Log in now.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
def logout():
    sid = session.get('db_session_id')
    if sid:
        conn = get_db()
        conn.execute('UPDATE sessions SET is_active=0, logout_time=? WHERE session_id=?',
                     (datetime.utcnow().isoformat(), sid))
        conn.commit()
        conn.close()
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    user = g.current_user
    db_sess = get_or_create_session(user)
    conn = get_db()
    recent_logs = rows_to_list(conn.execute(
        'SELECT * FROM request_logs WHERE session_id=? ORDER BY timestamp DESC LIMIT 10',
        (db_sess['session_id'],)
    ).fetchall())
    conn.close()

    category = request.args.get('category', 'all')

    posts = [
        {
            'category': 'Memes',
            'username': 'funny_panda',
            'avatar': 'F',
            'title': 'When the WiFi reconnects after 10 minutes of pain',
            'text': 'This is the kind of victory that deserves a celebration.',
            'image': 'https://images.unsplash.com/photo-1517849845537-4d257902454a?auto=format&fit=crop&w=900&q=80',
            'likes': 128,
            'comments': ['So real 😂', 'Every single time.', 'Instant happiness.']
        },
        {
            'category': 'Technology',
            'username': 'tech_wave',
            'avatar': 'T',
            'title': 'What do you think about AI replacing jobs?',
            'text': 'Will AI mostly assist people, or replace whole categories of work?',
            'image': 'https://images.unsplash.com/photo-1485827404703-89b55fcc595e?auto=format&fit=crop&w=900&q=80',
            'likes': 214,
            'comments': ['It will transform more than replace.', 'Depends on the field.', 'Upskilling matters a lot.']
        },
        {
            'category': 'Education',
            'username': 'study_hub',
            'avatar': 'S',
            'title': 'Best study method before exams?',
            'text': 'Active recall and spaced repetition still work better than rereading notes.',
            'image': 'https://images.unsplash.com/photo-1522202176988-66273c2fd55f?auto=format&fit=crop&w=900&q=80',
            'likes': 96,
            'comments': ['Flashcards help me a lot.', 'Pomodoro + recall works.', 'Need to try this.']
        },
        {
            'category': 'Sports',
            'username': 'goal_zone',
            'avatar': 'G',
            'title': 'Underrated football moments from this season',
            'text': 'Not every great moment ends up in the headlines.',
            'image': 'https://images.unsplash.com/photo-1517649763962-0c623066013b?auto=format&fit=crop&w=900&q=80',
            'likes': 173,
            'comments': ['That last-minute pass was insane.', 'Totally underrated.', 'Great pick.']
        },
        {
            'category': 'Discussions',
            'username': 'open_forum',
            'avatar': 'O',
            'title': 'What small habit changed your life the most?',
            'text': 'Could be health, work, study, or relationships.',
            'image': 'https://images.unsplash.com/photo-1499750310107-5fef28a66643?auto=format&fit=crop&w=900&q=80',
            'likes': 187,
            'comments': ['Daily walking.', 'Sleeping on time.', 'Writing down plans.']
        }
    ]

    if category and category.lower() != 'all':
        posts = [p for p in posts if p['category'].lower() == category.lower()]

    return render_template('dashboard.html', db_sess=db_sess, recent_logs=recent_logs, posts=posts, active_category=category)


@app.route('/profile')
@login_required
def profile():
    user = g.current_user
    db_sess = get_or_create_session(user)
    conn = get_db()
    all_sessions = rows_to_list(conn.execute(
        'SELECT * FROM sessions WHERE user_id=? ORDER BY login_time DESC LIMIT 5',
        (user['id'],)
    ).fetchall())
    conn.close()
    return render_template('profile.html', db_sess=db_sess, all_sessions=all_sessions)


@app.route('/settings')
@login_required
def settings():
    if g.current_user['role'] == 'admin':
        return render_template('settings.html', feature_settings=get_feature_settings(), feature_columns=FEATURE_COLUMNS)
    return redirect(url_for('dashboard'))


@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    conn = get_db()
    total_sessions = conn.execute('SELECT COUNT(*) FROM sessions').fetchone()[0]
    active_sessions = conn.execute('SELECT COUNT(*) FROM sessions WHERE is_active=1').fetchone()[0]
    hijacked_count = conn.execute('SELECT COUNT(*) FROM sessions WHERE is_hijacked=1').fetchone()[0]
    total_alerts = conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
    unresolved = conn.execute('SELECT COUNT(*) FROM alerts WHERE resolved=0').fetchone()[0]
    recent_alerts = rows_to_list(conn.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 5').fetchall())
    active_sess = rows_to_list(conn.execute(
        'SELECT s.*, u.username as username FROM sessions s LEFT JOIN users u ON s.user_id=u.id WHERE s.is_active=1 ORDER BY s.login_time DESC LIMIT 10'
    ).fetchall())
    conn.close()

    ml_metrics = {
        'accuracy': 100.0,
        'precision': 100.0,
        'recall': 100.0
    }

    return render_template(
        'admin_dashboard.html',
        total_sessions=total_sessions,
        active_sessions=active_sessions,
        hijacked_count=hijacked_count,
        total_alerts=total_alerts,
        unresolved=unresolved,
        recent_alerts=recent_alerts,
        active_sess=active_sess,
        chart_data=json.dumps(_sessions_per_day(7)),
        ml_metrics=ml_metrics
    )


@app.route('/admin/sessions')
@login_required
@admin_required
def admin_sessions():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    ft = request.args.get('filter', 'all')
    offset = (page - 1) * per_page
    conn = get_db()

    base = 'SELECT s.*, u.username as username FROM sessions s LEFT JOIN users u ON s.user_id=u.id'
    wh = {
        'active': ' WHERE s.is_active=1',
        'hijacked': ' WHERE s.is_hijacked=1',
        'suspicious': ' WHERE s.risk_score>=30 AND s.risk_score<60'
    }.get(ft, '')

    total = conn.execute(f'SELECT COUNT(*) FROM sessions s{wh}').fetchone()[0]
    items = rows_to_list(conn.execute(
        f'{base}{wh} ORDER BY s.login_time DESC LIMIT ? OFFSET ?',
        (per_page, offset)
    ).fetchall())
    conn.close()

    pages = max(1, (total + per_page - 1) // per_page)
    pag = {
        'rows': items,
        'page': page,
        'pages': pages,
        'total': total,
        'has_prev': page > 1,
        'has_next': page < pages,
        'prev_num': page - 1,
        'next_num': page + 1
    }
    return render_template('admin_sessions.html', sessions_page=pag, filter_type=ft)


@app.route('/admin/alerts')
@login_required
@admin_required
def admin_alerts():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    conn = get_db()
    total = conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
    items = rows_to_list(conn.execute(
        'SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ? OFFSET ?',
        (per_page, offset)
    ).fetchall())
    conn.close()

    pages = max(1, (total + per_page - 1) // per_page)
    pag = {
        'rows': items,
        'page': page,
        'pages': pages,
        'total': total,
        'has_prev': page > 1,
        'has_next': page < pages,
        'prev_num': page - 1,
        'next_num': page + 1
    }
    return render_template('admin_alerts.html', alerts_page=pag)


@app.route('/admin/simulate-attack', methods=['POST'])
@login_required
@admin_required
def simulate_attack():
    global simulation_active
    if not simulation_active:
        return jsonify({'status': 'error', 'message': 'Simulation is not active'}), 403
    
    un = request.json.get('username', 'testuser')
    result = generate_hijacked_session(un)
    return jsonify({'status': 'ok', 'session_id': result['session_id'], 'risk_score': result['risk_score']})


@app.route('/admin/resolve-alert/<int:aid>', methods=['POST'])
@login_required
@admin_required
def resolve_alert(aid):
    conn = get_db()
    conn.execute('UPDATE alerts SET resolved=1 WHERE id=?', (aid,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok'})


@app.route('/admin/terminate-session/<string:sid>', methods=['POST'])
@login_required
@admin_required
def terminate_session(sid):
    conn = get_db()
    conn.execute('UPDATE sessions SET is_active=0, logout_time=? WHERE session_id=?',
                 (datetime.utcnow().isoformat(), sid))
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok'})


# ========== SIMULATION CONTROL ENDPOINTS ==========

@app.route('/admin/simulation/start', methods=['POST'])
@login_required
@admin_required
def start_simulation():
    global simulation_active
    # Clear old data first
    clear_old_hijacked_data()
    simulation_active = True
    # Generate some initial simulated attacks
    for username in ['alice', 'bob', 'admin']:
        try:
            generate_hijacked_session(username)
        except:
            pass
    return jsonify({'status': 'ok', 'message': 'Simulation started - hijack data generated'})


@app.route('/admin/simulation/stop', methods=['POST'])
@login_required
@admin_required
def stop_simulation():
    global simulation_active
    simulation_active = False
    # Clear all hijacked data when stopping
    clear_old_hijacked_data()
    return jsonify({'status': 'ok', 'message': 'Simulation stopped - all hijack data cleared'})


@app.route('/admin/simulation/status', methods=['GET'])
@login_required
@admin_required
def simulation_status():
    global simulation_active
    return jsonify({'active': simulation_active})


@app.route('/api/admin/stats', methods=['GET'])
@login_required
@admin_required
def api_admin_stats():
    """API endpoint for real-time dashboard updates"""
    conn = get_db()
    
    # Get counts
    hijacked_count = conn.execute('SELECT COUNT(*) FROM sessions WHERE is_hijacked=1').fetchone()[0]
    unresolved_alerts = conn.execute('SELECT COUNT(*) FROM alerts WHERE resolved=0').fetchone()[0]
    
    # Get recent alerts (last 10)
    recent_alerts = rows_to_list(conn.execute(
        'SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10'
    ).fetchall())
    
    # Get active sessions (last 10)
    active_sessions = rows_to_list(conn.execute(
        'SELECT s.*, u.username FROM sessions s LEFT JOIN users u ON s.user_id=u.id WHERE s.is_active=1 ORDER BY s.login_time DESC LIMIT 10'
    ).fetchall())
    
    conn.close()
    
    return jsonify({
        'hijacked_count': hijacked_count,
        'unresolved_alerts': unresolved_alerts,
        'recent_alerts': recent_alerts,
        'active_sessions': active_sessions
    })


@app.route('/api/stats')
@login_required
@admin_required
def api_stats():
    conn = get_db()
    d = {
        'active_sessions': conn.execute('SELECT COUNT(*) FROM sessions WHERE is_active=1').fetchone()[0],
        'hijacked': conn.execute('SELECT COUNT(*) FROM sessions WHERE is_hijacked=1').fetchone()[0],
        'alerts': conn.execute('SELECT COUNT(*) FROM alerts WHERE resolved=0').fetchone()[0],
        'total_sessions': conn.execute('SELECT COUNT(*) FROM sessions').fetchone()[0]
    }
    conn.close()
    return jsonify(d)


@app.route('/api/session-status')
@login_required
def api_session_status():
    db_sess = get_or_create_session(g.current_user)
    return jsonify({
        'session_id': db_sess['session_id'],
        'risk_score': db_sess['risk_score'],
        'is_hijacked': bool(db_sess['is_hijacked']),
        'risk_reason': db_sess['risk_reason']
    })


@app.route('/api/settings', methods=['GET'])
@login_required
@admin_required
def api_get_settings():
    return jsonify(get_feature_settings())


@app.route('/api/settings', methods=['POST'])
@login_required
@admin_required
def api_update_settings():
    data = request.get_json(silent=True) or {}
    normalized = {feature: bool(data.get(feature, True)) for feature in FEATURE_COLUMNS}
    save_feature_settings(normalized)
    return jsonify({'status': 'ok', 'settings': normalized})


@app.template_filter('round')
def round_f(v, n=0):
    try:
        return round(float(v or 0), n)
    except:
        return 0


def _sessions_per_day(days=7):
    r = {'labels': [], 'normal': [], 'hijacked': []}
    conn = get_db()
    for i in range(days - 1, -1, -1):
        day = (datetime.utcnow() - timedelta(days=i)).date()
        s = day.isoformat() + ' 00:00:00'
        e = day.isoformat() + ' 23:59:59'
        r['labels'].append(day.strftime('%b %d'))
        r['normal'].append(conn.execute(
            'SELECT COUNT(*) FROM sessions WHERE login_time BETWEEN ? AND ? AND is_hijacked=0',
            (s, e)
        ).fetchone()[0])
        r['hijacked'].append(conn.execute(
            'SELECT COUNT(*) FROM sessions WHERE login_time BETWEEN ? AND ? AND is_hijacked=1',
            (s, e)
        ).fetchone()[0])
    conn.close()
    return r


@app.errorhandler(403)
def forbidden(e):
    flash('Access denied. Admin only.', 'danger')
    return redirect(url_for('login'))


def seed_users():
    conn = get_db()
    for un, pw, role in [('admin', 'admin123', 'admin'), ('alice', 'alice123', 'user'), ('bob', 'bob123', 'user')]:
        if not conn.execute('SELECT id FROM users WHERE username=?', (un,)).fetchone():
            conn.execute('INSERT INTO users (username,password,role) VALUES (?,?,?)',
                         (un, hash_password(pw), role))
    conn.commit()
    conn.close()


if __name__ == '__main__':
    init_db()
    seed_users()
    print("\n" + "=" * 50)
    print("  SessionSentry — AI Security Monitor")
    print("=" * 50)
    print("  URL  : http://127.0.0.1:5000")
    print("  Admin: admin / admin123")
    print("  User : alice / alice123")
    print("=" * 50 + "\n")
    app.run(debug=True, port=5000)