import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Create additionnal tables in the database :

# One table to record symbols (ID and Symbol)
symbols_table = db.execute("CREATE TABLE IF NOT EXISTS symbols (id INTEGER, symbol TEXT NOT NULL, PRIMARY KEY(id))")

# One table to track transactions (ID, ID User, ID Symbol, Type(sale or purchase), shares, unit value)
transactions_history_table = db.execute("CREATE TABLE IF NOT EXISTS transactions_history (id INTEGER, id_symbol INTEGER, id_user INTEGER, id_transaction_type INTEGER, shares INTEGER, unit_value NUMERIC NOT NULL, transaction_dt DATE, PRIMARY KEY(id))")

# One table for transaction type
transactions_type_table = db.execute("CREATE TABLE IF NOT EXISTS transactions_type (id INTEGER, transaction_type TEXT NOT NULL, PRIMARY KEY(id))")

# Create the initial transactions type values
def create_transaction_type(type_value):
    check_value_exist = db.execute("SELECT transaction_type FROM transactions_type WHERE transaction_type = ?", type_value)

    if check_value_exist == []:
        create_new_value = db.execute("INSERT INTO transactions_type (transaction_type) VALUES (?)", type_value)

create_transaction_type("purchase")
create_transaction_type("sale")

# One table to manage users's wallet (ID, ID Symbol, ID User, shares)
wallets_table = db.execute("CREATE TABLE IF NOT EXISTS wallets (id INTEGER, id_symbol INTEGER, id_user INTEGER, shares INTEGER, PRIMARY KEY(id))")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    return apology("TODO")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        #redirect user to homepage
        return redirect("/")

    else:
        return render_template("buy.html")

    #return apology("TODO")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "POST":

        quote_symbol = request.form.get("symbol")
        quote_data = lookup(quote_symbol)

        # print(quote_data)
        if quote_data == None:
            return apology("invalid symbol", 403)
        else:
            return render_template("quoted.html", quote_data=quote_data)

    elif request.method == "GET":
        return render_template("quote.html")

    # return apology("TODO")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        password_repeat = request.form.get("password-repeat")

        test_name_exist = db.execute("SELECT username FROM users WHERE username = ?", username)

        # print(username, password, password_repeat)
        # print(test_name_exist)

        if not username:
            return apology("must provide username", 403)

        elif test_name_exist:
            return apology("username not available", 403)

        if not password:
            return apology("must provide password", 403)

        elif password != password_repeat:
            return apology("Password and confirm password does not match", 403)

        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8);

        print("hashed pw" + hashed_pw)
        # print(check_password_hash(hashed_pw, password))

        insert_new_user = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed_pw)

        return redirect("/")

    elif request.method == "GET":
        return render_template("register.html")


    # return apology("TODO")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    return apology("TODO")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
