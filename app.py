import os
import datetime
import base64
import pytz

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, lookup, usd
from email.message import EmailMessage
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials


# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///fido.db")



@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Shows pets owned by user and food schedule"""
    if request.method == "GET":
        date = db.execute("SELECT date_time FROM users WHERE id = ?", session["user_id"])
        date = date[0]["date_time"]
        date = datetime.datetime.strptime(date, '%Y-%m-%d').date()
        new_date = datetime.date.today()
        if new_date > date:
            db.execute("UPDATE pets SET breakfast = 'hungry', lunch = 'hungry', dinner = 'hungry' WHERE user_id = ?", session["user_id"])
            db.execute("UPDATE users SET date_time = ? WHERE id = ?", new_date, session["user_id"])
        rows = db.execute("SELECT petname, id, breakfast, lunch, dinner FROM pets WHERE user_id = ?", session["user_id"])
        pets = []
        for row in rows:
            pets.append(row)
        return render_template("index.html", pets=pets)
    else:
        if not request.form.get("meal"):
            delete_pet = request.form.get("delete")
            db.execute("DELETE FROM pets WHERE id = ?", delete_pet)
            return redirect("/")
        else:
            meal = request.form.get("meal")
            pet = request.form.get("pet")
            db.execute("UPDATE pets SET ? = 'fed' WHERE user_id = ? AND petname = ?", meal, session["user_id"], pet)
            email = db.execute("SELECT email FROM users WHERE user_id = ?", session["user_id"])
            # Update with Company Email as sender
            send_email('mclarenmanmatt@gmail.com', email, pet, meal)
            return redirect("/")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/addpet", methods=["GET", "POST"])
@login_required
def addPet():
    if request.method == "POST":
        if not request.form.get("pet"):
            return apology("must provide Pet Name", 400)
        pet = request.form.get("pet")
        db.execute("INSERT INTO pets (petname, user_id) VALUES (?, ?)", pet, session["user_id"])
        return redirect("/")
    else:
        return render_template("addpet.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Check if Username Submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Check if Password Submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Check to see if password and confirmation match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        # Check to see if username is taken
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        if len(rows) > 0:
            return apology("this username already exists", 400)

        # Store username and hash in the table and redirect to homepage
        elif len(rows) == 0:
            hash = generate_password_hash(request.form.get("password"))
            username = request.form.get("username")
            UTC = pytz.utc
            date = datetime.datetime.now(UTC).date()
            email = request.form.get("email")
            timezone = request.form.get("timezone")
            db.execute("INSERT INTO users (username, hash, date_time, email, timezone) VALUES(?, ?, ?, ?, ?)", username, hash, date, email, timezone)
            return redirect("/")
    else:
        timezones=[]
        for tz in pytz.all_timezones:
            timezones.append(tz)
        return render_template("register.html", timezones=timezones)


# Function utilizing the gmail API to send automated emails
def send_email(sender, recipient, pet, meal):
    """Create and send an email message
    Print the returned  message id
    Returns: Message object, including message id

    Load pre-authorized user credentials from the environment.
    See https://developers.google.com/identity
    for guides on implementing OAuth2 for the application.
    """
    SCOPES = ['https://www.googleapis.com/auth/gmail.send']
    creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    try:
        service = build('gmail', 'v1', credentials=creds)
        message = EmailMessage()

        message.set_content('Yay! ' + pet + ' has been fed ' + meal + '!')

        message['To'] = recipient
        message['From'] = sender
        message['Subject'] = pet + ' has been fed ' + meal + '!'

        # encoded message
        encoded_message = base64.urlsafe_b64encode(message.as_bytes()) \
            .decode()

        create_message = {
            'raw': encoded_message
        }
        # pylint: disable=E1101
        send_message = (service.users().messages().send
                        (userId="me", body=create_message).execute())
        print(F'Message Id: {send_message["id"]}')
    except HttpError as error:
        print(F'An error occurred: {error}')
        send_message = None
    return send_message
