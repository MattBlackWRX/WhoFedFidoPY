import os
import datetime
import base64
import pytz

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required
from email.message import EmailMessage
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow


# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

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
        # Pull last time stamp from database
        date_time = db.execute("SELECT date_time FROM users WHERE id = ?", session["user_id"])
        date_time = date_time[0]["date_time"]
        # Convert text to date time object
        date_time = datetime.datetime.strptime(date_time, '%Y-%m-%d %H:%M:%S')
        # Pull in Timezone from database
        tz = db.execute("SELECT timezone FROM users WHERE id = ?", session["user_id"])
        tz = pytz.timezone(tz[0]["timezone"])
        date_time_tz = pytz.utc.localize(date_time, is_dst=None).astimezone(tz)
        # Generate new timestamp in UTC and convert to user timezone
        utc = pytz.utc
        new_date_time_utc = datetime.datetime.now(utc)
        new_date_time_tz = new_date_time_utc.astimezone(tz)
        # Compare new date to old date, if new day, reset food schedule in datebase
        if new_date_time_tz.date() > date_time_tz.date():
            db.execute("UPDATE pets SET breakfast = 'hungry', lunch = 'hungry', dinner = 'hungry' WHERE user_id = ?", session["user_id"])
            db.execute("UPDATE users SET date_time = ? WHERE id = ?", new_date_time_utc, session["user_id"])
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
            meal_status = db.execute("SELECT * from pets WHERE user_id = ? AND petname = ?", session["user_id"], pet)
            meal_status = meal_status[0][meal]
            if meal_status == "hungry":
                db.execute("UPDATE pets SET ? = 'fed' WHERE user_id = ? AND petname = ?", meal, session["user_id"], pet)
                email = db.execute("SELECT email FROM users WHERE id = ?", session["user_id"])
                email = email[0]["email"]
                # Update with Company Email as sender
                send_email('mclarenmanmatt@gmail.com', email, pet, meal)
                return redirect("/")
            else:
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
            utc = pytz.utc
            date_time = datetime.datetime.now(utc)
            email = request.form.get("email")
            timezone = request.form.get("timezone")
            db.execute("INSERT INTO users (username, hash, date_time, email, timezone) VALUES(?, ?, ?, ?, ?)", username, hash, date_time, email, timezone)
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
    
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is created automatically when the authorization flow completes for the first time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
        # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    
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
