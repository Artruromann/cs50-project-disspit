
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session,url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

app = Flask(__name__)
db = SQL("sqlite:///disspit.db")

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

#another functions
@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

def login_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function

def error(msg = "", code = 400):
    return render_template("error.html",notform = True, msg = msg, n = code)

#app routes
@app.route("/")
def unloggedHome():
    return render_template("notlogged.html")



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log in user"""
    session.clear()

    if request.method == "POST":
        # Validate form inputs
        if not request.form.get("username"):
            return error("must provide username", 403)
        elif not request.form.get("password"):
            return error("must provide password", 403)

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
            return error("invalid username and/or password", 403)


        session["user_id"] = rows[0]["id"]

        return redirect("/")

    # Render the login page for GET request
    return render_template("login.html")



@app.route("/register", methods = ["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confpassword")

        # Input validation
        if not username or not password or not confirmation:
            return error("All fields must be filled", 400)
        if password != confirmation:
            return error("Passwords do not match", 400)
        if username == password:
            return error("Password cant be the same as username")
        # Check if username exists
        usrows = db.execute("SELECT * FROM users WHERE username = ?", username)
        for i in db.execute("SELECT password FROM users"):
            if check_password_hash(i['password'], password):
                return error("Password is already in use")
            
        if len(usrows) > 0:
            return error("Username already taken", 400)

        # Insert new user
        hashed_password = generate_password_hash(password)
        db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'user')", username, hashed_password)

        flash("Registration successful! Please log in.")
        return redirect(url_for("login"))
    return render_template("register.html")
    

@app.route("/home")
def home():
    
    return error()

