import sqlite3
from datetime import datetime


DATABASE = "database/scans.db"


# ---------------------------------------------------------
# DATABASE CONNECTION
# ---------------------------------------------------------

def get_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------
# INITIALIZE DATABASE
# ---------------------------------------------------------

def init_db():

    conn = get_connection()

    # -----------------------------------------------------
    # USERS TABLE
    # -----------------------------------------------------

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # -----------------------------------------------------
    # SCANS TABLE
    # -----------------------------------------------------

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            duration REAL
        )
    """)

    # -----------------------------------------------------
    # PORTS TABLE
    # -----------------------------------------------------

    conn.execute("""
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            port INTEGER,
            protocol TEXT,
            state TEXT,
            service TEXT,
            product TEXT,
            version TEXT,
            FOREIGN KEY (scan_id)
                REFERENCES scans(id)
        )
    """)

    conn.commit()
    conn.close()


# ---------------------------------------------------------
# USER AUTHENTICATION
# ---------------------------------------------------------

def create_user(username, email, password_hash):

    conn = get_connection()

    try:

        cursor = conn.execute(
            """
            INSERT INTO users
            (username, email, password_hash, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                username,
                email,
                password_hash,
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )
        )

        conn.commit()

        return cursor.lastrowid

    except sqlite3.IntegrityError:

        return None

    finally:

        conn.close()


def get_user_by_username(username):

    conn = get_connection()

    user = conn.execute(
        """
        SELECT
            id,
            username,
            email,
            password_hash,
            created_at
        FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()

    conn.close()

    return user


def get_user_by_email(email):

    conn = get_connection()

    user = conn.execute(
        """
        SELECT
            id,
            username,
            email,
            password_hash,
            created_at
        FROM users
        WHERE email = ?
        """,
        (email,)
    ).fetchone()

    conn.close()

    return user


# ---------------------------------------------------------
# SAVE SCAN
# ---------------------------------------------------------

def save_scan(target, duration, results):

    conn = get_connection()

    scan_date = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    cursor = conn.execute(
        """
        INSERT INTO scans
        (target, scan_date, duration)
        VALUES (?, ?, ?)
        """,
        (
            target,
            scan_date,
            duration
        )
    )

    scan_id = cursor.lastrowid

    for result in results:

        conn.execute(
            """
            INSERT INTO ports
            (
                scan_id,
                port,
                protocol,
                state,
                service,
                product,
                version
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                result.get("port"),
                result.get("protocol"),
                result.get("state"),
                result.get("service"),
                result.get("product"),
                result.get("version")
            )
        )

    conn.commit()
    conn.close()

    return scan_id


# ---------------------------------------------------------
# SCAN HISTORY
# ---------------------------------------------------------

def get_scan_history():

    conn = get_connection()

    scans = conn.execute(
        """
        SELECT
            id,
            target,
            scan_date,
            duration
        FROM scans
        ORDER BY id DESC
        """
    ).fetchall()

    conn.close()

    return scans


# ---------------------------------------------------------
# DASHBOARD DATA
# ---------------------------------------------------------

def get_dashboard_data():

    conn = get_connection()

    total_scans = conn.execute(
        "SELECT COUNT(*) FROM scans"
    ).fetchone()[0]

    total_ports = conn.execute(
        "SELECT COUNT(*) FROM ports"
    ).fetchone()[0]

    latest = conn.execute(
        """
        SELECT target
        FROM scans
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()

    latest_target = (
        latest["target"]
        if latest
        else "No scans yet"
    )

    conn.close()

    return (
        total_scans,
        total_ports,
        latest_target
    )


# ---------------------------------------------------------
# GET SINGLE SCAN
# ---------------------------------------------------------

def get_scan_by_id(scan_id):

    conn = get_connection()

    scan = conn.execute(
        """
        SELECT
            id,
            target,
            scan_date,
            duration
        FROM scans
        WHERE id = ?
        """,
        (scan_id,)
    ).fetchone()

    conn.close()

    return scan


# ---------------------------------------------------------
# GET PORTS FOR SCAN
# ---------------------------------------------------------

def get_ports_by_scan_id(scan_id):

    conn = get_connection()

    ports = conn.execute(
        """
        SELECT
            port,
            protocol,
            state,
            service,
            product,
            version
        FROM ports
        WHERE scan_id = ?
        ORDER BY port
        """,
        (scan_id,)
    ).fetchall()

    conn.close()

    return ports