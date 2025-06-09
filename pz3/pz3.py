import sqlite3
from datetime import datetime, timedelta
import uuid

def create_database():
    conn = sqlite3.connect('security_events.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS EventSources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            location TEXT,
            type TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS EventTypes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type_name TEXT UNIQUE NOT NULL,
            severity TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS SecurityEvents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME NOT NULL,
            source_id INTEGER,
            event_type_id INTEGER,
            message TEXT,
            ip_address TEXT,
            username TEXT,
            FOREIGN KEY (source_id) REFERENCES EventSources(id),
            FOREIGN KEY (event_type_id) REFERENCES EventTypes(id)
        )
    ''')
    conn.commit()
    return conn, cursor

def insert_initial_data(cursor, conn):
    event_types = [
        ('Login Success', 'Informational'),
        ('Login Failed', 'Warning'),
        ('Port Scan Detected', 'Warning'),
        ('Malware Alert', 'Critical')
    ]
    cursor.executemany('INSERT OR IGNORE INTO EventTypes (type_name, severity) VALUES (?, ?)', event_types)
    event_sources = [
        ('Firewall_A', '192.168.1.1', 'Firewall'),
        ('Web_Server_Logs', '192.168.1.2', 'Web Server'),
        ('IDS_Sensor_B', '192.168.1.3', 'IDS')
    ]
    cursor.executemany('INSERT OR IGNORE INTO EventSources (name, location, type) VALUES (?, ?, ?)', event_sources)
    test_events = [
        (datetime.now() - timedelta(hours=1), 1, 1, 'Successful login attempt', '192.168.2.1', 'user1'),
        (datetime.now() - timedelta(hours=2), 2, 2, 'Failed login attempt', '192.168.2.2', 'user2'),
        (datetime.now() - timedelta(minutes=30), 3, 3, 'Port scan detected from remote host', '192.168.2.3', None),
        (datetime.now() - timedelta(days=2), 1, 4, 'Malware detected in system', '192.168.2.4', None),
        (datetime.now() - timedelta(hours=3), 2, 2, 'Failed login attempt', '192.168.2.2', 'user2'),
        (datetime.now() - timedelta(minutes=45), 2, 2, 'Failed login attempt', '192.168.2.2', 'user2'),
        (datetime.now() - timedelta(minutes=50), 2, 2, 'Failed login attempt', '192.168.2.2', 'user2'),
        (datetime.now() - timedelta(minutes=55), 2, 2, 'Failed login attempt', '192.168.2.2', 'user2'),
        (datetime.now() - timedelta(minutes=58), 2, 2, 'Failed login attempt', '192.168.2.2', 'user2'),
        (datetime.now() - timedelta(hours=4), 1, 1, 'Successful login attempt', '192.168.2.5', 'user3'),
        (datetime.now() - timedelta(days=1), 3, 4, 'Critical malware alert', None, None),
        (datetime.now() - timedelta(hours=5), 2, 2, 'Failed login attempt', '192.168.2.6', 'user4')
    ]
    cursor.executemany('''
        INSERT INTO SecurityEvents (timestamp, source_id, event_type_id, message, ip_address, username)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', test_events)
    conn.commit()

def register_event_source(cursor, conn, name, location, type_):
    try:
        cursor.execute('INSERT INTO EventSources (name, location, type) VALUES (?, ?, ?)', (name, location, type_))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        print(f"Source {name} already exists")
        return False

def register_event_type(cursor, conn, type_name, severity):
    try:
        cursor.execute('INSERT INTO EventTypes (type_name, severity) VALUES (?, ?)', (type_name, severity))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        print(f"Event type {type_name} already exists")
        return False

def log_security_event(cursor, conn, source_id, event_type_id, message, ip_address=None, username=None):
    timestamp = datetime.now()
    cursor.execute('''
        INSERT INTO SecurityEvents (timestamp, source_id, event_type_id, message, ip_address, username)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, source_id, event_type_id, message, ip_address, username))
    conn.commit()

def get_failed_logins_last_24h(cursor):
    query = '''
        SELECT se.*, es.name, et.type_name
        FROM SecurityEvents se
        JOIN EventSources es ON se.source_id = es.id
        JOIN EventTypes et ON se.event_type_id = et.id
        WHERE et.type_name = 'Login Failed'
        AND se.timestamp >= ?
    '''
    cursor.execute(query, (datetime.now() - timedelta(hours=24),))
    return cursor.fetchall()

def detect_bruteforce_attempts(cursor, time_window_hours=1):
    query = '''
        SELECT se.ip_address, COUNT(*) as attempt_count
        FROM SecurityEvents se
        JOIN EventTypes et ON se.event_type_id = et.id
        WHERE et.type_name = 'Login Failed'
        AND se.timestamp >= ?
        AND se.ip_address IS NOT NULL
        GROUP BY se.ip_address
        HAVING attempt_count > 5
    '''
    cursor.execute(query, (datetime.now() - timedelta(hours=time_window_hours),))
    return cursor.fetchall()

def get_critical_events_last_week(cursor):
    query = '''
        SELECT es.name, COUNT(*) as event_count, GROUP_CONCAT(se.message) as messages
        FROM SecurityEvents se
        JOIN EventSources es ON se.source_id = es.id
        JOIN EventTypes et ON se.event_type_id = et.id
        WHERE et.severity = 'Critical'
        AND se.timestamp >= ?
        GROUP BY es.name
    '''
    cursor.execute(query, (datetime.now() - timedelta(days=7),))
    return cursor.fetchall()

def search_events_by_keyword(cursor, keyword):
    query = '''
        SELECT se.*, es.name, et.type_name
        FROM SecurityEvents se
        JOIN EventSources es ON se.source_id = es.id
        JOIN EventTypes et ON se.event_type_id = et.id
        WHERE se.message LIKE ?
    '''
    cursor.execute(query, (f'%{keyword}%',))
    return cursor.fetchall()

def main():
    conn, cursor = create_database()
    insert_initial_data(cursor, conn)
    print("Registering new event source:")
    register_event_source(cursor, conn, "Test_Sensor", "192.168.1.4", "Sensor")
    print("\nRegistering new event type:")
    register_event_type(cursor, conn, "Test Event", "Low")
    print("\nFailed login attempts in last 24 hours:")
    failed_logins = get_failed_logins_last_24h(cursor)
    for event in failed_logins:
        print(event)
    print("\nPotential brute force attempts:")
    brute_force = detect_bruteforce_attempts(cursor)
    for ip, count in brute_force:
        print(f"IP: {ip}, Attempts: {count}")
    print("\nCritical events in last week:")
    critical_events = get_critical_events_last_week(cursor)
    for source, count, messages in critical_events:
        print(f"Source: {source}, Count: {count}")
    print("\nEvents containing 'malware':")
    malware_events = search_events_by_keyword(cursor, 'malware')
    for event in malware_events:
        print(event)
    conn.close()

if __name__ == "__main__":
    main()
