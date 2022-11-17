from flask import Flask, request, redirect, render_template, url_for, session
import ibm_db
import re

try:
    conn = ibm_db.connect(
        "DATABASE=bludb;HOSTNAME=19af6446-6171-4641-8aba-9dcff8e1b6ff.c1ogj3sd0tgtu0lqde00.databases.appdomain.cloud;PORT=30699;SECURITY=SSL;SSLServerCertificate=DigiCertGlobalRootCA.crt;PROTOCOL=TCPIP;UID=bsw94689;PWD=chzilTh2WOngq0iG;",
        '', '')
    print(conn)
    print("connection successfull")
except:
    print("Error in connection, sqlstate = ")
    errorState = ibm_db.conn_error()
    print(errorState)

app = Flask(__name__, static_url_path='/static')
app.secret_key = 'smartfashionrecommender'


@app.route('/')
def home():
    if 'loggedin' in session:
        return render_template('home.html', username=session['username'])

    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        email = request.form['email']
        password = request.form['password']
        checkuser = "SELECT * FROM USERS WHERE email=? AND password=?"
        stmt1 = ibm_db.prepare(conn, checkuser)
        ibm_db.bind_param(stmt1, 1, email)
        ibm_db.bind_param(stmt1, 2, password)
        ibm_db.execute(stmt1)
        account = ibm_db.fetch_tuple(stmt1)
        if account:

            session['loggedin'] = True
            session['id'] = account[0]
            session['username'] = account[1]

            return render_template("home.html")
        else:
            msg = "Invalid email-id or password!"
    return render_template("login.html", msg=msg)


@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        print(username, email, password)
        checkuser = "SELECT email FROM USERS WHERE email=?"
        stmt1 = ibm_db.prepare(conn, checkuser)
        ibm_db.bind_param(stmt1, 1, email)
        ibm_db.execute(stmt1)
        account = ibm_db.fetch_tuple(stmt1)
        print(account)
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            sql = "INSERT INTO USERS(username,email,password) VALUES(?,?,?)"
            stmt = ibm_db.prepare(conn, sql)
            ibm_db.bind_param(stmt, 1, username)
            ibm_db.bind_param(stmt, 2, email)
            ibm_db.bind_param(stmt, 3, password)
            ibm_db.execute(stmt)
            print(username, email, password)
            msg = 'You have successfully registered!'
            return redirect(url_for('home'))
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
    return render_template('signup.html', msg=msg)


if __name__ == '__main__':
    app.run(debug=True)