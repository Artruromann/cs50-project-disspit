
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session,url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

app = Flask(__name__)

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

def error(msg = "", code = 400):
   return render_template("error.html",notform =true, msg = msg, n = code)

@app.route("/dsvs")
def unloggedHome():

   return error()

@app.route("/login")
def login():
   return render_template("login.html")

@app.route("/")
def register():
   return render_template("register.html")


