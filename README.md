# Secure Digital Banking (Flask + SQLite)

A paperless banking website: 2-step login (PIN + OTP), trusted-device protection,
online service forms, and concurrency-safe transactions.

## Files
| File | Purpose |
|---|---|
| `app.py` | Backend (Flask API + SQLite database) |
| `static/index.html`, `style.css`, `app.js` | Frontend (served by the backend) |
| `test_backend.py` | 60 automated tests (unit, integration, security, concurrency) |
| `admin_tools.py` | Bank-staff commands (unlock account, reset device, review requests) |
| `requirements.txt` | Python packages needed |

## Run on your computer
    pip install -r requirements.txt
    python app.py
Open http://127.0.0.1:5000

## Run the tests
    python -m unittest test_backend -v

## Deploy on Render (free)
1. Put these files in a GitHub repository (app.py and requirements.txt must be at the top level).
2. On render.com: New > Web Service > connect the repository.
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app --workers 2 --threads 4 --timeout 60`
5. Instance type: Free.
6. Environment variables: `PIN_PEPPER` = any long random text, `DEMO_MODE` = 1
7. Deploy. Your link will look like https://your-name.onrender.com

## Demo script (for viva)
1. Create an account, then log in: PIN, then the OTP shown on screen (demo mode).
2. Deposit, withdraw, transfer to a second account, view history.
3. Forms tab: submit a KYC update.
4. Log out, tick "pretend I'm on a new device", log in again: money actions are blocked.
5. Enter a wrong PIN 3 times: the account locks.

## Bank-staff commands
    python admin_tools.py unlock 1001
    python admin_tools.py reset-device 1001
    python admin_tools.py requests

## Known limits (prototype)
* OTP is shown on screen because no SMS service is connected (DEMO_MODE=1).
* Free Render hosting sleeps when idle (first load takes ~1 minute) and its disk is
  temporary, so accounts can be erased when the service restarts or redeploys.
* No real money or real bank is involved.
