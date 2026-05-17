# 🛡️ SessionSentry
### AI-Based Behavioral Session Hijacking Detection Framework

---

## 📌 What Is This?

SessionSentry is a complete AI-powered cybersecurity monitoring system that detects **session hijacking attacks** using behavioral analysis and Machine Learning (Random Forest).

Instead of simple IP-based rules, it monitors **19 behavioral features** in real-time and uses an ML model to classify sessions as:
- ✅ **Normal** (Risk Score 0–30)
- ⚠️ **Suspicious** (Risk Score 30–60)
- 🚨 **Hijacked** (Risk Score 60+)

---

## 🚀 Quick Start (Step-by-Step)

### Prerequisites
- Python 3.9+ installed
- VS Code (recommended)

---

### Step 1 — Open Project in VS Code

1. Extract/copy the `SessionSentry` folder somewhere on your computer
2. Open VS Code
3. Click **File → Open Folder** → select `SessionSentry`
4. Open the Terminal: press `` Ctrl+` `` (backtick)

---

### Step 2 — Create Virtual Environment

In the VS Code terminal, type these commands one by one:

```bash
# Create virtual environment
python -m venv venv

# Activate it (Windows PowerShell)
venv\Scripts\activate

# OR activate it (Mac/Linux)
source venv/bin/activate
```

You should see `(venv)` appear at the start of the terminal line.

---

### Step 3 — Install Dependencies

```bash
pip install flask pandas numpy scikit-learn joblib
```

Wait for installation to finish (1–2 minutes).

---

### Step 4 — Train the ML Model

```bash
python ml/train_model.py
```

This will:
- Generate 700 synthetic sessions (500 normal + 200 hijacked)
- Train the Random Forest model
- Show accuracy metrics (expect ~100% on synthetic data)
- Save `ml/rf_model.pkl`

Expected output:
```
Accuracy    100.00%
Precision   100.00%
Recall      100.00%
F1 Score    100.00%
Model saved: ml/rf_model.pkl
```

---

### Step 5 — Run the Application

```bash
python app.py
```

You will see:
```
==================================================
  SessionSentry — AI Security Monitor
==================================================
  URL  : http://127.0.0.1:5000
  Admin: admin / admin123
  User : alice / alice123
==================================================
```

---

### Step 6 — Open in Browser

Open your browser and go to:
```
http://127.0.0.1:5000
```

---

## 🔐 Login Credentials

| Role  | Username | Password  |
|-------|----------|-----------|
| Admin | admin    | admin123  |
| User  | alice    | alice123  |
| User  | bob      | bob123    |

---

## 🗺️ Application URLs

### User Pages
| URL | Description |
|-----|-------------|
| `http://127.0.0.1:5000/login` | Login page |
| `http://127.0.0.1:5000/register` | Register new account |
| `http://127.0.0.1:5000/dashboard` | User dashboard with session status |
| `http://127.0.0.1:5000/profile` | User profile + session history |
| `http://127.0.0.1:5000/logout` | Logout |

### Admin Pages
| URL | Description |
|-----|-------------|
| `http://127.0.0.1:5000/admin` | Admin security overview + charts |
| `http://127.0.0.1:5000/admin/sessions` | All sessions management |
| `http://127.0.0.1:5000/admin/alerts` | Security alerts |

---

## 🎭 Demo: Simulate a Hijacking Attack

### Method 1: Built-in Simulator (Easiest)
1. Log in as **admin**
2. Go to Admin Dashboard (`/admin`)
3. Scroll to **"Attack Simulation"** at the bottom
4. Type `alice` in the username field
5. Click **"Simulate Hijack Attack"**
6. Watch the alert appear and dashboard update!

### Method 2: Manual (With Burp Suite)
See `attacks/burp_simulation_notes.txt` for detailed instructions.

---

## 📁 Project Structure

```
SessionSentry/
│
├── app.py                     ← Main Flask application (run this!)
├── config.py                  ← App configuration
├── models.py                  ← SQLite database layer
├── requirements.txt           ← Python dependencies
│
├── ml/
│   ├── train_model.py         ← Run to train ML model
│   ├── feature_extractor.py   ← Extracts 19 behavioral features
│   ├── detector.py            ← Real-time detection engine
│   ├── rf_model.pkl           ← Trained model (after training)
│   └── scaler.pkl             ← Feature scaler
│
├── database/
│   └── database.db            ← SQLite database (auto-created)
│
├── dataset/
│   └── session_dataset.csv    ← Training dataset (auto-generated)
│
├── templates/
│   ├── base.html              ← Base layout
│   ├── login.html             ← Login page
│   ├── register.html          ← Register page
│   ├── dashboard.html         ← User dashboard
│   ├── profile.html           ← User profile
│   ├── settings.html          ← Settings page
│   ├── admin_dashboard.html   ← Admin overview + charts
│   ├── admin_sessions.html    ← Sessions management
│   └── admin_alerts.html      ← Alerts management
│
├── static/
│   ├── css/style.css          ← Dark cyber design
│   └── js/dashboard.js        ← Frontend interactivity
│
└── attacks/
    └── burp_simulation_notes.txt  ← Burp Suite demo guide
```

---

## 🧠 ML Features (19 Total)

| Category | Features |
|----------|----------|
| Network | ip_change, ip_frequency, ip_mismatch |
| Browser/Device | browser_change, os_change, cookie_reuse |
| Session | session_duration, session_idle_time |
| Requests | request_rate, request_variance, post_get_ratio, total_requests |
| Navigation | page_depth, page_sequence_entropy, admin_page_attempt, direct_page_access |
| Timing | click_interval_avg, click_interval_std, night_activity_flag |

---

## 🔍 How Detection Works

```
User Request Arrives
        ↓
Log to database (ip, browser, page, time, method)
        ↓
Every 3 requests → Extract 19 features
        ↓
Rule-based Risk Score (0–100)
        ↓
Random Forest ML Prediction (0=Normal / 1=Hijacked)
        ↓
Combined Decision
        ↓
If Hijacked:
  → Update session risk_score
  → Create alert
  → Show in admin dashboard
```

---

## 🛑 Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: flask` | Run: `pip install flask` |
| `No module named 'sklearn'` | Run: `pip install scikit-learn` |
| `rf_model.pkl not found` | Run: `python ml/train_model.py` first |
| Port 5000 already in use | Change port in `app.py`: `app.run(port=5001)` |
| Database error | Delete `database/database.db` and restart |

---

## 📊 Demo Script for Presentation

1. **Start the app**: `python app.py`
2. **Login as alice** → Browse dashboard, profile, settings (generates normal behavior logs)
3. **Login as admin** → Show the Admin Dashboard with live session table
4. **Simulate Attack** → Click "Simulate Hijack Attack" with username "alice"
5. **Watch alert appear** → Risk Score 87.5 | Reason: IP changed, browser changed, high request rate
6. **Go to Alerts page** → Show the alert with full details
7. **Terminate session** → Click the ban button on the hijacked session
8. **Explain ML model** → Show `ml/train_model.py` and `ml/feature_extractor.py`

---

*Built with Flask, SQLite, scikit-learn Random Forest, Chart.js*
