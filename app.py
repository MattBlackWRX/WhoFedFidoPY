import datetime
import pytz

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, send_email


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

db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, username TEXT NOT NULL, hash TEXT NOT NULL, date_time TEXT, email TEXT, timezone TEXT)")
db.execute("CREATE UNIQUE INDEX IF NOT EXISTS username ON users (username)")
db.execute("CREATE TABLE IF NOT EXISTS pets (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, petname TEXT NOT NULL, breakfast TEXT NOT NULL DEFAULT hungry, lunch TEXT NOT NULL DEFAULT hungry, dinner TEXT NOT NULL DEFAULT hungry, user_id INTEGER, user_two_id INTEGER, FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY (user_two_id) REFERENCES users(id))")


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
            db.execute("UPDATE pets SET breakfast = 'hungry', lunch = 'hungry', dinner = 'hungry' WHERE user_id = ? OR user_two_id = ?", session["user_id"], session["user_id"])
            db.execute("UPDATE users SET date_time = ? WHERE id = ?", new_date_time_utc, session["user_id"])
        rows = db.execute("SELECT petname, id, breakfast, lunch, dinner FROM pets WHERE user_id = ? OR  user_two_id = ?", session["user_id"], session["user_id"])
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
            pet_id = request.form.get("pet_id")
            pet = db.execute("SELECT * from pets WHERE id = ?", pet_id)
            meal_status = pet[0][meal]
            pet_name = pet[0]['petname']
            if meal_status == "hungry":
                db.execute("UPDATE pets SET ? = 'fed' WHERE id = ?", meal, pet_id)
                email_list = db.execute("SELECT email FROM users WHERE id = (SELECT user_id FROM pets WHERE id = ?) OR (SELECT user_two_id FROM pets WHERE id = ?)", pet_id, pet_id)
                for n in range(len(email_list)):
                    email = email_list[n]["email"]
                    # Update with appropriate email as sender
                    sender_email = "whofedfido@gmail.com"
                    send_email(sender_email, email, pet_name, meal)
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
            return apology("Must provide a username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("Must provide a password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("Invalid username and/or password", 400)

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
        # Email form to search for an already registered pet, if not searching continue
        if not request.form.get("email"):
            # Pet ID form is to add the user to the pet as a second owner, if not continue
            if not request.form.get("pet_id"):
                # If no information is given, return apology
                if not request.form.get("pet"):
                    return apology("Must provide a Pet Name or Email", 400)
                pet = request.form.get("pet")
                db.execute("INSERT INTO pets (petname, user_id) VALUES (?, ?)", pet, session["user_id"])
                return redirect("/")
            # Add user as a second owner
            pet_id = request.form.get("pet_id")
            db.execute("UPDATE pets SET user_two_id = ? WHERE id = ?", session["user_id"], pet_id)
        # Seach the database for pets registered to the email given and render template
        email = request.form.get("email")
        rows = db.execute("SELECT petname, id FROM pets WHERE user_id = (SELECT id FROM users WHERE email = ?)", email)
        pets = []
        for row in rows:
            pets.append(row)
        return render_template("addpet.html", pets=pets)

    else:
        return render_template("addpet.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Check if Username Submitted
        if not request.form.get("username"):
            return apology("Must provide a username", 400)

        # Check if Email Submitted
        if not request.form.get("email"):
            return apology("Must provide an email", 400)

        # Check if Password Submitted
        elif not request.form.get("password"):
            return apology("Must provide a password", 400)

        # Check to see if password and confirmation match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords do not match", 400)

        # Check to see if username is taken
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        if len(rows) > 0:
            return apology("This username already exists", 400)

        # Check to see if email is taken
        rows = db.execute("SELECT * FROM users WHERE email = ?", request.form.get("email"))
        if len(rows) > 0:
            return apology("This email is already registered")
        
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
