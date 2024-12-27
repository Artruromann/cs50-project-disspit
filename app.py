
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from functools import wraps
from flask_socketio import SocketIO, emit
import random

app = Flask(__name__)
db = SQL("sqlite:///disspit.db")

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = "secret"
app.config["DEBUG"] = True
Session(app)

socketio = SocketIO(app)

chatusers ={}

#functions
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

def error(msg="", code=400):
    return render_template("error.html", notform=True, msg=msg, n=code)

def generate_id(n, search): 
    id = random.randint(10**(n-1), ((10**n) - 1))
    if  len(db.execute(search, id)) > 0:
        generate_id(n, search)
    
    return id
        

#routes
@app.route("/")
def unloggedHome():
    return render_template("notlogged.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        if not request.form.get("username"):
            return error("must provide username", 403)
        elif not request.form.get("password"):
            return error("must provide password", 403)

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
            return error("invalid username and/or password", 403)

        session["user_id"] = rows[0]["id"]
        session["username"] = rows[0]["username"]
        return redirect("/home")

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confpassword")

        if not username or not password or not confirmation:
            return error("All fields must be filled", 400)
        if password != confirmation:
            return error("Passwords do not match", 400)
        if username == password:
            return error("Password can't be the same as username")

        usrows = db.execute("SELECT * FROM users WHERE username = ?", username)
        for i in db.execute("SELECT password FROM users"):
            if check_password_hash(i['password'], password):
                return error("Password is already in use")

        if len(usrows) > 0:
            return error("Username already taken", 400)

        hashed_password = generate_password_hash(password)
        db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'user')", username, hashed_password)

        flash("Registration successful! Please log in.")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/home")
@login_required
def home():
    return render_template("home.html")

@app.route("/newboard", methods=["GET", "POST"])
@login_required
def newboard():
    return render_template("newboard.html")

@app.route("/chats")
@login_required
def chats():
    userid = session["user_id"]
    chatlistprompt = """SELECT 
        chats.id,
        chats.userid1 AS userid1,
        user1.username AS username1,
        chats.userid2 AS userid2,
        user2.username AS username2,
        chats.last_interaction
    FROM chats
    JOIN users AS user1 ON chats.userid1 = user1.id
    JOIN users AS user2 ON chats.userid2 = user2.id
    WHERE chats.userid1 = ? OR chats.userid2 = ?
    ORDER BY chats.last_interaction ASC
    """

    chatlist = db.execute(chatlistprompt, userid, userid)
    
    if chatlist == None:
        chatlist = []
    

    friendslen = len(chatlist)


    return render_template("chats.html",friendslen=friendslen, chatlist=chatlist, userid=userid)

@app.route("/chatboard")
@login_required
def chatboard():
    
    return render_template("chatboard.html")

 

#Socketio events for user chats
@socketio.on("connect")
def handle_connect():
    print("Client connected")

@socketio.on("user_join")
def handle_user_join():
    print(f"user {session["username"]} joined to chats")
    chatusers[session['username']] = request.sid

@socketio.on("new message")
def handle_newmessage(message, receiver, receiverid):
    
    if receiverid == None:
        return error("Receiver not found", 404)
    
    userid = session["user_id"]
    print(f"{session['username']} Sent a new message to {receiver}({receiverid}): {message}")
    
    #save message to database
    id = generate_id(6, "SELECT id FROM messages WHERE id = ?")
    chatidprompt = "SELECT id FROM chats WHERE userid1 = ? AND userid2 = ? OR userid1 = ? AND userid2 = ?"

    getchatid = db.execute(chatidprompt, userid, int(receiverid), int(receiverid), userid)
    if len(getchatid) == 0:
        return error("Chat not found", 404)
    else:
        print(f"Chat found: {getchatid[0]['id']}")

    chatid= getchatid[0]['id']
    insertmessage = "INSERT INTO messages (id, chatid ,senderid, receiverid, content, timestamp) VALUES (? ,? ,?, ?, ?, ?)"
    db.execute(insertmessage, id, chatid, userid, receiverid, message, datetime.now())
    
    #send message
    emit("chat", {"message": message, "receiverid":receiverid}, broadcast = True)

@socketio.on("load messages")
def handle_loadmessages(friendid):
    userid = session["user_id"]
    chatidprompt = "SELECT id FROM chats WHERE userid1 = ? AND userid2 = ? OR userid1 = ? AND userid2 = ?"
    getchatid = db.execute(chatidprompt, userid, int(friendid), int(friendid), userid)
    
    if len(getchatid) == 0:
        return error("Chat not found", 404)
    
    chatid = getchatid[0]['id']

    chatmessages = db.execute("SELECT * FROM messages WHERE chatid = ? ORDER BY timestamp ASC", chatid)
    
    if len(chatmessages) > 0:
        print(f"Messages from chat {chatid} loaded")

    emit("print messages", chatmessages)




