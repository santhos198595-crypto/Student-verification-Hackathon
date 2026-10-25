"""
CrescentRide - shared rides for Crescent students going home.

Install:
    pip install flask werkzeug

Configure these environment variables before running:
    CRESCENT_EMAIL_DOMAIN   Official college email domain, without @
    SECRET_KEY              Long random secret used to sign login sessions
    SMTP_HOST               SMTP server used to send verification emails
    SMTP_PORT               Usually 587
    SMTP_USER               SMTP username
    SMTP_PASSWORD           SMTP password or app password
    SMTP_FROM               Sender email address

Then run:
    python crescentride.py

Open http://127.0.0.1:5000

This is a hackathon prototype, not a production-ready ride-sharing service.
"""
import os
import re
import secrets
import smtplib
import sqlite3
from datetime import datetime, timedelta
from email.message import EmailMessage
from functools import wraps

from flask import Flask, request, jsonify, g, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Set COOKIE_SECURE=1 when deployed behind HTTPS.
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)
DB = os.environ.get("CRESCENTRIDE_DB", "crescentride.db")
EMAIL_DOMAIN = os.environ.get("CRESCENT_EMAIL_DOMAIN", "").strip().lower().lstrip("@")
OTP_MINUTES = 10


# ---------- Database helpers ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    """Create tables and add new columns when upgrading an older prototype DB."""
    db = sqlite3.connect(DB)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            college_email TEXT,
            student_id TEXT,
            password_hash TEXT,
            email_verified INTEGER NOT NULL DEFAULT 0,
            verification_code_hash TEXT,
            verification_expires TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS rides (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            driver_id INTEGER NOT NULL,
            destination TEXT NOT NULL,
            depart_time TEXT NOT NULL,
            seats_left INTEGER NOT NULL,
            cost_per_head INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (driver_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ride_id INTEGER NOT NULL,
            rider_id INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (ride_id, rider_id),
            FOREIGN KEY (ride_id) REFERENCES rides(id),
            FOREIGN KEY (rider_id) REFERENCES users(id)
        );
    """)

    # Migrate the original prototype's users table without deleting existing data.
    existing = {row[1] for row in db.execute("PRAGMA table_info(users)").fetchall()}
    migrations = {
        "college_email": "ALTER TABLE users ADD COLUMN college_email TEXT",
        "student_id": "ALTER TABLE users ADD COLUMN student_id TEXT",
        "password_hash": "ALTER TABLE users ADD COLUMN password_hash TEXT",
        "email_verified": "ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0",
        "verification_code_hash": "ALTER TABLE users ADD COLUMN verification_code_hash TEXT",
        "verification_expires": "ALTER TABLE users ADD COLUMN verification_expires TEXT",
        "created_at": "ALTER TABLE users ADD COLUMN created_at TEXT",
    }
    for column, sql in migrations.items():
        if column not in existing:
            db.execute(sql)

    # Prevent duplicate bookings even if requests arrive close together.
    db.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_booking
        ON bookings(ride_id, rider_id)
    """)
    db.commit()
    db.close()


# ---------- Authentication / validation helpers ----------
def json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def college_email_error(email):
    if not EMAIL_DOMAIN:
        return "Server setup is incomplete: configure CRESCENT_EMAIL_DOMAIN."
    if not email or len(email) > 254:
        return "A valid college email is required."
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return "Enter a valid email address."
    if email.rsplit("@", 1)[1].lower() != EMAIL_DOMAIN:
        return f"Use your official college email ending in @{EMAIL_DOMAIN}."
    return None


def send_verification_email(email, code):
    host = os.environ.get("SMTP_HOST")
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASSWORD")
    sender = os.environ.get("SMTP_FROM", user or "")
    if not all([host, user, password, sender]):
        raise RuntimeError(
            "Email sending is not configured. Set SMTP_HOST, SMTP_USER, "
            "SMTP_PASSWORD and SMTP_FROM."
        )

    msg = EmailMessage()
    msg["Subject"] = "CrescentRide email verification"
    msg["From"] = sender
    msg["To"] = email
    msg.set_content(
        f"Your CrescentRide verification code is: {code}\n\n"
        f"This code expires in {OTP_MINUTES} minutes. "
        "If you did not request it, you can ignore this email."
    )
    port = int(os.environ.get("SMTP_PORT", "587"))
    with smtplib.SMTP(host, port, timeout=15) as server:
        server.starttls()
        server.login(user, password)
        server.send_message(msg)


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            return jsonify(error="Please log in first."), 401
        user = get_db().execute(
            "SELECT id, email_verified FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if not user:
            session.clear()
            return jsonify(error="Account not found. Please log in again."), 401
        if not user["email_verified"]:
            session.clear()
            return jsonify(error="Verify your college email before using CrescentRide."), 403
        return fn(*args, **kwargs)
    return wrapper


# ---------- Routes ----------
@app.route("/")
def home():
    return jsonify(
        message="CrescentRide API is running",
        authentication="college email verification required",
        endpoints=[
            "POST /register",
            "POST /verify-email",
            "POST /login",
            "POST /logout",
            "GET /me",
            "POST /rides",
            "GET /rides",
            "POST /rides/<ride_id>/join",
        ],
    )


@app.route("/register", methods=["POST"])
def register():
    data = json_body()
    name = str(data.get("name", "")).strip()
    phone = str(data.get("phone", "")).strip()
    email = str(data.get("college_email", "")).strip().lower()
    password = data.get("password", "")
    student_id = str(data.get("student_id", "")).strip() or None

    if not name or not phone or not email or not isinstance(password, str):
        return jsonify(error="name, phone, college_email and password are required."), 400
    if len(name) > 100 or len(phone) > 30:
        return jsonify(error="Name or phone number is too long."), 400
    if len(password) < 10:
        return jsonify(error="Password must be at least 10 characters long."), 400
    email_error = college_email_error(email)
    if email_error:
        return jsonify(error=email_error), 400

    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE lower(college_email) = ?", (email,)).fetchone():
        return jsonify(error="An account already exists for this college email."), 409

    code = f"{secrets.randbelow(1_000_000):06d}"
    code_hash = generate_password_hash(code)
    expires = (datetime.utcnow() + timedelta(minutes=OTP_MINUTES)).isoformat(timespec="seconds")

    try:
        # Send first so a failed SMTP setup does not leave an unusable account.
        send_verification_email(email, code)
    except (RuntimeError, OSError, smtplib.SMTPException, ValueError) as exc:
        app.logger.warning("Verification email could not be sent: %s", exc)
        return jsonify(
            error="Could not send verification email. Check the email server configuration."
        ), 503

    try:
        cur = db.execute(
            """INSERT INTO users
               (name, phone, college_email, student_id, password_hash,
                email_verified, verification_code_hash, verification_expires)
               VALUES (?, ?, ?, ?, ?, 0, ?, ?)""",
            (name, phone, email, student_id, generate_password_hash(password),
             code_hash, expires),
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        return jsonify(error="Could not create account; check whether the email is already registered."), 409

    return jsonify(
        user_id=cur.lastrowid,
        message="Account created. Enter the code sent to your college email at POST /verify-email.",
        verification_expires_in_minutes=OTP_MINUTES,
    ), 201


@app.route("/verify-email", methods=["POST"])
def verify_email():
    data = json_body()
    email = str(data.get("college_email", "")).strip().lower()
    code = str(data.get("code", "")).strip()
    if not email or not re.fullmatch(r"\d{6}", code):
        return jsonify(error="college_email and a 6-digit code are required."), 400

    db = get_db()
    user = db.execute(
        """SELECT id, verification_code_hash, verification_expires, email_verified
           FROM users WHERE lower(college_email) = ?""",
        (email,),
    ).fetchone()
    if not user:
        return jsonify(error="Account not found."), 404
    if user["email_verified"]:
        return jsonify(message="Email is already verified."), 200

    try:
        expires = datetime.fromisoformat(user["verification_expires"])
    except (TypeError, ValueError):
        return jsonify(error="Verification code is invalid or expired. Register again or contact support."), 400
    if datetime.utcnow() > expires:
        return jsonify(error="Verification code has expired. Please request a new code."), 400
    if not user["verification_code_hash"] or not check_password_hash(user["verification_code_hash"], code):
        return jsonify(error="Incorrect verification code."), 400

    db.execute(
        """UPDATE users SET email_verified = 1,
           verification_code_hash = NULL, verification_expires = NULL
           WHERE id = ?""",
        (user["id"],),
    )
    db.commit()
    return jsonify(message="College email verified. You can now log in."), 200


@app.route("/login", methods=["POST"])
def login():
    data = json_body()
    email = str(data.get("college_email", "")).strip().lower()
    password = data.get("password", "")
    if not email or not isinstance(password, str):
        return jsonify(error="college_email and password are required."), 400

    user = get_db().execute(
        """SELECT id, password_hash, email_verified FROM users
           WHERE lower(college_email) = ?""",
        (email,),
    ).fetchone()
    if not user or not user["password_hash"] or not check_password_hash(user["password_hash"], password):
        return jsonify(error="Invalid email or password."), 401
    if not user["email_verified"]:
        return jsonify(error="Verify your college email before logging in."), 403

    session.clear()
    session["user_id"] = user["id"]
    return jsonify(message="Logged in successfully.", user_id=user["id"]), 200


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify(message="Logged out successfully."), 200


@app.route("/me", methods=["GET"])
@login_required
def me():
    user = get_db().execute(
        """SELECT id, name, college_email, student_id, email_verified
           FROM users WHERE id = ?""",
        (session["user_id"],),
    ).fetchone()
    return jsonify(dict(user)), 200


@app.route("/rides", methods=["POST"])
@login_required
def offer_ride():
    data = json_body()
    destination = str(data.get("destination", "")).strip().lower()
    depart_time = str(data.get("depart_time", "")).strip()
    seats = data.get("seats")
    cost = data.get("cost", 0)

    if not destination or len(destination) > 120:
        return jsonify(error="A destination (up to 120 characters) is required."), 400
    try:
        departure = datetime.strptime(depart_time, "%Y-%m-%d %H:%M")
    except ValueError:
        return jsonify(error="depart_time must look like 2026-10-30 16:30."), 400
    if departure <= datetime.now():
        return jsonify(error="Departure time must be in the future."), 400
    if isinstance(seats, bool) or not isinstance(seats, int) or not 1 <= seats <= 8:
        return jsonify(error="seats must be a whole number between 1 and 8."), 400
    if isinstance(cost, bool) or not isinstance(cost, int) or not 0 <= cost <= 100000:
        return jsonify(error="cost must be a whole number from 0 to 100000."), 400

    db = get_db()
    cur = db.execute(
        """INSERT INTO rides
           (driver_id, destination, depart_time, seats_left, cost_per_head)
           VALUES (?, ?, ?, ?, ?)""",
        (session["user_id"], destination, depart_time, seats, cost),
    )
    db.commit()
    return jsonify(ride_id=cur.lastrowid), 201


@app.route("/rides", methods=["GET"])
@login_required
def find_rides():
    """Search: /rides?destination=tambaram&time=2026-10-30%2016:00"""
    dest = request.args.get("destination", "").strip().lower()
    time = request.args.get("time")
    db = get_db()
    rows = db.execute(
        """SELECT r.id, r.destination, r.depart_time, r.seats_left,
                  r.cost_per_head, u.name AS driver
           FROM rides r
           JOIN users u ON u.id = r.driver_id
           WHERE r.destination LIKE ? AND r.seats_left > 0
             AND r.depart_time >= ?
           ORDER BY r.depart_time""",
        (f"%{dest}%", datetime.now().strftime("%Y-%m-%d %H:%M")),
    ).fetchall()

    rides = [dict(row) for row in rows]
    if time:
        try:
            wanted = datetime.strptime(time, "%Y-%m-%d %H:%M")
        except ValueError:
            return jsonify(error="time must look like 2026-10-30 16:00."), 400
        rides = [
            ride for ride in rides
            if abs((datetime.strptime(ride["depart_time"], "%Y-%m-%d %H:%M") - wanted).total_seconds())
            <= 2 * 3600
        ]
    # Phone numbers and student IDs are deliberately not included in search results.
    return jsonify(rides), 200


@app.route("/rides/<int:ride_id>/join", methods=["POST"])
@login_required
def join_ride(ride_id):
    rider_id = session["user_id"]  # Never trust a user ID supplied by the client.
    db = get_db()

    try:
        # Lock the write transaction while checking and taking a seat.
        db.execute("BEGIN IMMEDIATE")
        ride = db.execute("SELECT * FROM rides WHERE id = ?", (ride_id,)).fetchone()
        if not ride:
            db.rollback()
            return jsonify(error="Ride not found."), 404
        if ride["driver_id"] == rider_id:
            db.rollback()
            return jsonify(error="You cannot join your own ride."), 400
        if ride["seats_left"] <= 0:
            db.rollback()
            return jsonify(error="Ride is full."), 400
        already = db.execute(
            "SELECT 1 FROM bookings WHERE ride_id = ? AND rider_id = ?",
            (ride_id, rider_id),
        ).fetchone()
        if already:
            db.rollback()
            return jsonify(error="You have already booked this ride."), 400

        db.execute(
            "INSERT INTO bookings (ride_id, rider_id) VALUES (?, ?)",
            (ride_id, rider_id),
        )
        update = db.execute(
            "UPDATE rides SET seats_left = seats_left - 1 WHERE id = ? AND seats_left > 0",
            (ride_id,),
        )
        if update.rowcount != 1:
            db.rollback()
            return jsonify(error="Ride is full."), 400
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        return jsonify(error="You have already booked this ride."), 400
    except sqlite3.Error:
        db.rollback()
        app.logger.exception("Booking transaction failed")
        return jsonify(error="Could not complete booking. Please try again."), 500

    return jsonify(message="Seat booked!", seats_left=ride["seats_left"] - 1), 200


if __name__ == "__main__":
    init_db()
    # Debug mode is useful locally but must be disabled for deployment.
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
