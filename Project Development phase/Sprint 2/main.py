import http.client
import json
from flask import Flask, request, redirect, render_template, url_for, session
import ibm_db
import re
from werkzeug.utils import secure_filename
import math

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
def dashboard():
    return render_template('dashboard.html')


@app.route('/home')
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


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == "POST":
        file = request.form['selectfile']
    return render_template('upload.html')


@app.route('/getnutrition', methods=['GET', 'POST'])
def getnutrition():
    if request.method == "POST":
        name = request.form['name']
        conn = http.client.HTTPSConnection("spoonacular-recipe-food-nutrition-v1.p.rapidapi.com")
        headers = {
            'X-RapidAPI-Key': "b83d346435msh8fe6686c34fa340p1091cajsn36d5e66c8425",
            'X-RapidAPI-Host': "http://spoonacular-recipe-food-nutrition-v1.p.rapidapi.com/"
        }
        conn.request("GET", "/recipes/guessNutrition?title = " + name, headers=headers)
        res = conn.getresponse()
        data = res.read()
        r = json.loads(data)
        val = len(r)

        if val == 2:
            return render_template("getnutrition.html", msg="invalid")
        else:
            calories = r["calories"]["value"]
            fat = r["fat"]["value"]
            protein = r["protein"]["value"]
            carbs = r["carbs"]["value"]

            def add():
                conn = ibm_db.connect(
                    "DATABASE=bludb;HOSTNAME=19af6446-6171-4641-8aba-9dcff8e1b6ff.c1ogj3sd0tgtu0lqde00.databases.appdomain.cloud;PORT=30699;SECURITY=SSL;SSLServerCertificate=DigiCertGlobalRootCA.crt;PROTOCOL=TCPIP;UID=bsw94689;PWD=chzilTh2WOngq0iG;",
                    '', '')
                insert_sql = "INSERT INTO HISTORY VALUES (?, ?, ?, ?, ?)"
                calories1 = round(calories, 2)
                protein1 = round(protein, 2)
                fat1 = round(fat, 2)
                carbs1 = round(carbs, 2)
                print(calories1)
                prep_stmt = ibm_db.prepare(conn, insert_sql)
                ibm_db.bind_param(prep_stmt, 1, name)
                ibm_db.bind_param(prep_stmt, 2, calories)
                ibm_db.bind_param(prep_stmt, 3, protein)
                ibm_db.bind_param(prep_stmt, 4, fat)
                ibm_db.bind_param(prep_stmt, 5, carbs)

                ibm_db.execute(prep_stmt)

            add()
            return render_template('getnutrition.html', calories=calories, fat=fat, protein=protein, carbs=carbs)
    return render_template('getnutrition.html')


@app.route('/up')
def up():
    return render_template('up.html')


@app.route('/uploader', methods=['GET', 'POST'])
def uploader():
    if request.method == 'POST':
        f = request.files['file']
        f.save(secure_filename(f.filename))
        print(f.filename)
        # n=f.filename
        # file_extns=n.split(".")
        # q=repr(file_extns[0])
        # w=repr(file_extns[-1])
        # a2 = q.strip("\'")
        # print(q)
        a = f.filename
        b = a[:-1]
        c = b[:-1]
        d = c[:-1]
        e = d[:-1]
        print(e)

        return render_template('getnut.html', msg=e)


@app.route('/display')
def display():
    history = []
    sql = "SELECT * FROM historyi"
    stmt = ibm_db.exec_immediate(conn, sql)
    dictionary = ibm_db.fetch_both(stmt)
    while dictionary != False:
        # print ("The Name is : ",  dictionary)
        history.append(dictionary)
        dictionary = ibm_db.fetch_both(stmt)
    if history:
        return render_template('display.html', history=history)


if __name__ == '__main__':
    app.run(debug=False)
