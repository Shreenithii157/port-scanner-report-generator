import sqlite3
from datetime import datetime


DATABASE = "database/scans.db"


# --------------------------------
# DATABASE CONNECTION
# --------------------------------

def get_connection():

    conn = sqlite3.connect(DATABASE)

    conn.row_factory = sqlite3.Row

    return conn


# --------------------------------
# INITIALIZE DATABASE
# --------------------------------

def init_db():

    conn = get_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            duration REAL,
            cve_count INTEGER DEFAULT 0
        )
    """)

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
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    # --------------------------------
    # ADD CVE COLUMN TO OLD DATABASE
    # --------------------------------

    columns = conn.execute(
        "PRAGMA table_info(scans)"
    ).fetchall()

    column_names = [
        column["name"]
        for column in columns
    ]

    if "cve_count" not in column_names:

        conn.execute("""
            ALTER TABLE scans
            ADD COLUMN cve_count INTEGER DEFAULT 0
        """)

    conn.commit()

    conn.close()


# --------------------------------
# SAVE SCAN
# --------------------------------

def save_scan(
    target,
    duration,
    results,
    cve_count=0
):

    conn = get_connection()

    scan_date = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    cursor = conn.execute(
        """
        INSERT INTO scans
        (
            target,
            scan_date,
            duration,
            cve_count
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            target,
            scan_date,
            duration,
            cve_count
        )
    )

    scan_id = cursor.lastrowid

    # --------------------------------
    # SAVE PORT RESULTS
    # --------------------------------

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


# --------------------------------
# GET SCAN HISTORY
# --------------------------------

def get_scan_history():

    conn = get_connection()

    scans = conn.execute(
        """
        SELECT
            id,
            target,
            scan_date,
            duration,
            cve_count
        FROM scans
        ORDER BY id DESC
        """
    ).fetchall()

    conn.close()

    return scans


# --------------------------------
# GET DASHBOARD DATA
# --------------------------------

def get_dashboard_data():

    conn = get_connection()

    # Total scans

    total_scans = conn.execute(
        """
        SELECT COUNT(*)
        FROM scans
        """
    ).fetchone()[0]


    # Total open ports

    total_ports = conn.execute(
        """
        SELECT COUNT(*)
        FROM ports
        """
    ).fetchone()[0]


    # Total CVE matches

    total_vulnerabilities = conn.execute(
        """
        SELECT COALESCE(
            SUM(cve_count),
            0
        )
        FROM scans
        """
    ).fetchone()[0]


    # Latest target

    latest = conn.execute(
        """
        SELECT target
        FROM scans
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()


    if latest:

        latest_target = latest["target"]

    else:

        latest_target = "No scans yet"


    conn.close()


    return (
        total_scans,
        total_ports,
        total_vulnerabilities,
        latest_target
    )


# --------------------------------
# GET INDIVIDUAL SCAN
# --------------------------------

def get_scan_by_id(scan_id):

    conn = get_connection()

    scan = conn.execute(
        """
        SELECT
            id,
            target,
            scan_date,
            duration,
            cve_count
        FROM scans
        WHERE id = ?
        """,
        (scan_id,)
    ).fetchone()

    conn.close()

    return scan


# --------------------------------
# GET PORTS FOR A SCAN
# --------------------------------

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