import pathlib
import threading
import requests
import sqlite3
import time
import re
from flask import render_template, request, redirect, url_for, session
from werkzeug.exceptions import abort
from werkzeug.security import generate_password_hash, check_password_hash

from app import app

ALLOWED_EXTENSIONS = {'.txt'}
apikey = 'c0ff6705b8d801472df90ddac0efde4fdec0464ffc282f3f2cd11d335017eea2'


def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


def get_report(report_id):
    conn = get_db_connection()
    report_hashes = conn.execute('SELECT hashes.id, hash_value, fortinet_result, positives, scan_date '
                                 'FROM (SELECT hash_id, report_id FROM hash_report_bridge WHERE report_id = ?) '
                                 'AS SOURCE '
                                 'JOIN hashes ON SOURCE.hash_id = hashes.id',
                                 (report_id,)).fetchall()
    report_info = conn.execute('SELECT id, title, datetime(created, "localtime") AS dt FROM reports WHERE id = ?',
                               (report_id,)).fetchall()
    conn.close()
    if report_hashes is None:
        abort(404)
    return report_info[0], report_hashes


def allowed_file(filename):
    return pathlib.Path(filename).suffix in ALLOWED_EXTENSIONS


def get_info_from_vt(item):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': apikey, 'resource': item}
    response = requests.get(url, params=params)
    while response.status_code != 200:
        print("waiting for the other server to respond!")
        time.sleep(5)
        response = requests.get(url, params=params)
    print("response = ", response)
    result = response.json()
    return result


def get_hash_info_from_inner_db(cur, item):
    try:
        record = cur.execute('SELECT id, hash_value, fortinet_result, positives, scan_date, '
                             'Cast((JulianDay("now") - JulianDay(scan_date)) AS INTEGER) AS diff '
                             'FROM hashes WHERE hash_value = ?', (item,)).fetchone()
    except Exception as e:
        print(f"An error happened during accessing the db and getting the result for hash {item}")
        print(e)
    return record


def insert_or_update_hash_table(cur, item, record, result):
    hash_value = item
    fortinet_result = result["scans"]["Fortinet"]["result"] if "scans" in result and \
                                                               "Fortinet" in result["scans"] else None
    positives = result["positives"] if "positives" in result else None
    scan_date = result["scan_date"] if "scan_date" in result else None
    print(hash_value, fortinet_result, positives, scan_date)
    if not record:
        # insert if not found
        try:
            cur.execute(
                'INSERT INTO hashes (hash_value, fortinet_result, positives, scan_date) VALUES (?, ?, ?, ?)',
                (hash_value, fortinet_result, positives, scan_date))
        except Exception as e:
            print(f"An error happened during insertion of hash {hash_value}")
            print(e)
        else:
            print("Inserted in the DB")

    else:
        # update if found but old result
        try:
            cur.execute(
                'UPDATE hashes SET fortinet_result = ?, positives = ?, scan_date = ? WHERE hash_value = ?',
                (fortinet_result, positives, scan_date, hash_value))
        except Exception as e:
            print(f"An error happened during update of hash {hash_value}")
            print(e)
        else:
            print("Updated in the DB")


def add_hash_id_to_hashlist(cur, hash_id_list, item):
    try:
        hash_id = cur.execute('SELECT id FROM hashes WHERE hash_value = ?', (item,)).fetchone()
        hash_id_list.append(int(hash_id[0]))
    except Exception as e:
        print("An error happened during accessing the database and getting hash id")
        print(e)


def add_this_report_to_internal_db(cur, user_id):
    report_id = -1
    try:
        report_count = cur.execute('SELECT count(id) FROM reports WHERE user_id = (?) ORDER BY id DESC LIMIT 1',
                                   (user_id,)).fetchone()
        report_name = f"Report Number {int(report_count[0]) + 1}"
    except Exception as e:
        print(f"An error happened during accessing the database and getting the previous reports for user {user_id}")
        print(e)

    else:
        try:
            cur.execute('INSERT INTO reports (title, user_id) VALUES (?, ?)', (report_name, user_id))
            report_id = cur.execute('SELECT last_insert_rowid() FROM reports').fetchone()
        except Exception as e:
            print(f"An error happened during accessing the database and adding report {report_id} for user {user_id}")
            print(e)
        finally:
            return report_id


def connect_report_to_hash_list(cur, hash_id_list, report_id):
    try:
        for hid in hash_id_list:
            cur.execute('INSERT INTO hash_report_bridge (hash_id, report_id) VALUES (?, ?)', (hid, int(report_id[0])))
    except Exception as e:
        print(f"An error happened during accessing the database and connecting hash ids to report {int(report_id[0])}")
        print(e)


def create_report(*args):
    print("Starting report creation")

    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    hash_id_list = []
    user_id = args[0]
    items = args[1:]
    for item in items:
        record = get_hash_info_from_inner_db(cur, item)
        if not record or record[5] != 1:
            result = get_info_from_vt(item)

            insert_or_update_hash_table(cur, item, record, result)

        add_hash_id_to_hashlist(cur, hash_id_list, item)

    report_id = add_this_report_to_internal_db(cur, user_id)
    connect_report_to_hash_list(cur, hash_id_list, report_id)

    conn.commit()
    conn.close()


@app.route('/', methods=['GET'])
@app.route('/message=<message>', methods=['GET'])
def index(message=None):
    if 'loggedin' not in session:
        # User is loggedin show them the home page
        return redirect(url_for('login'))
    user_id = session["id"]
    username = session["username"]
    conn = get_db_connection()
    reports = conn.execute("SELECT id, title, datetime(created, 'localtime') AS dt FROM reports WHERE user_id = ?",
                           (user_id,)).fetchall()
    conn.close()
    return render_template('index.html', reports=reports, message=message, username=username)


@app.route('/', methods=['POST'])
@app.route('/message=<message>', methods=['POST'])
def upload_file(message=None):
    if 'file' not in request.files:
        return redirect(url_for('index', message='No file part'))
    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('index', message='No selected file'))
    if file and allowed_file(file.filename):
        lines = [str(line.decode('utf-8')) for line in file.read().splitlines()]
        user_id = session["id"]
        # creating a list of user_id and all lines to pass to threads
        user_and_lines = [user_id]
        for line in lines:
            user_and_lines.append(line)
        thread = threading.Thread(target=create_report, args=tuple(user_and_lines))
        thread.start()
    else:
        return redirect(url_for('index', message='Incorrect file type'))
    return redirect(url_for('index'))


@app.route('/about.html')
def about_page():
    return render_template('about.html')


@app.route('/<int:report_id>')
def generate_report(report_id):
    report_info, report_hashes = get_report(report_id)
    return render_template('report.html', report_info=report_info, report_hashes=report_hashes)


@app.route('/login/', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        cur = conn.cursor()
        account = cur.execute('SELECT id, username, password_hash FROM users WHERE username = (?)',
                              (username,)).fetchone()
        if account and check_password_hash(account[2], password):
            # Create session data
            session['loggedin'] = True
            session['id'] = account[0]
            session['username'] = account[1]
            return redirect(url_for('index'))
        else:
            # Account doesnt exist or username/password incorrect
            msg = 'Incorrect username/password!'

    return render_template('login.html', msg=msg)


@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        conn = sqlite3.connect('database.db')
        cur = conn.cursor()
        account = cur.execute('SELECT * FROM users WHERE username = (?)', (username,)).fetchone()

        # If account exists show error and validation checks
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password:
            msg = 'Please fill out the form!'
        else:
            # Account doesnt exists and the form data is valid
            cur.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password,))
            conn.commit()
            conn.close()
            msg = 'You have successfully registered!'
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
    return render_template('register.html', msg=msg)
