import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

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

# Create initial user table
users_table = db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, username TEXT NOT NULL, hash TEXT NOT NULL, cash NUMERIC NOT NULL DEFAULT 10000.00, PRIMARY KEY(id))")

# Create additionnal tables in the database :

# One table to record symbols (ID and Symbol)
symbols_table = db.execute("CREATE TABLE IF NOT EXISTS symbols (id INTEGER NOT NULL, symbol TEXT NOT NULL, PRIMARY KEY(id))")

# One table to track transactions (ID, ID User, ID Symbol, Type(sale or purchase), shares, unit value)
transactions_history_table = db.execute("CREATE TABLE IF NOT EXISTS transactions_history (id INTEGER NOT NULL, id_symbol INTEGER, id_user INTEGER, id_transaction_type INTEGER, shares INTEGER, unit_value NUMERIC NOT NULL, transaction_dt DATE, PRIMARY KEY(id))")

# One table for transaction type
transactions_type_table = db.execute("CREATE TABLE IF NOT EXISTS transactions_type (id INTEGER NOT NULL, transaction_type TEXT NOT NULL, PRIMARY KEY(id))")

# Create the initial transactions type values
def create_transaction_type(type_value):
    check_value_exist = db.execute("SELECT transaction_type FROM transactions_type WHERE transaction_type = ?", type_value)

    if check_value_exist == []:
        create_new_value = db.execute("INSERT INTO transactions_type (transaction_type) VALUES (?)", type_value)

create_transaction_type("purchase")
create_transaction_type("sale")

PURCHASE_ID = db.execute("SELECT id FROM transactions_type WHERE transaction_type = ?", "purchase")
SALE_ID = db.execute("SELECT id FROM transactions_type WHERE transaction_type = ?", "sale")

# One table to manage users's wallet (ID, ID Symbol, ID User, shares)
wallets_table = db.execute("CREATE TABLE IF NOT EXISTS wallets (id INTEGER NOT NULL, id_symbol INTEGER, id_user INTEGER, shares INTEGER, PRIMARY KEY(id))")

# function to update user's wallet
def update_wallet(wallet_share, stock_share, id_symbol):
    new_shares = wallet_share + stock_share
    update_wallet_db_request = db.execute("UPDATE wallets SET shares = ? WHERE id_symbol = ? AND id_user = ?", new_shares, id_symbol, session["user_id"])

#function to get user's cash
def get_user_cash_func(user_id):
    request = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    user_cash = request[0]["cash"]
    return user_cash

# function to update users' cash
def update_user_cash_func(cash_balance):
    request = db.execute("UPDATE users SET cash = ? WHERE id = ?", cash_balance, session["user_id"])


# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # get_user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash_value = round(get_user_cash_func(session["user_id"]), 2)
    get_wallet_list = db.execute("SELECT * FROM wallets WHERE id_user = ? AND shares > 0", session["user_id"])
    total_wallet_value = cash_value
    row_counter = 0

    def add_data_wallet_item(wallet_dict):
        get_symbol_label = db.execute("SELECT symbol FROM symbols WHERE id = ?", wallet_dict["id_symbol"])
        wallet_dict["label_symbol"] = get_symbol_label[0]["symbol"]
        get_symbol_data = lookup(wallet_dict["label_symbol"])
        wallet_dict["name_symbol"] = get_symbol_data["name"]
        wallet_dict["price_symbol"] = get_symbol_data["price"]
        wallet_dict["total_value"] = round(wallet_dict["price_symbol"] * wallet_dict["shares"], 2)

    for dict in get_wallet_list:
        add_data_wallet_item(dict)
        row_counter += 1
        row_even_odd = row_counter % 2

        if row_even_odd == 1:
            dict["row_style"] = "row-style-1"
        else:
            dict["row_style"] = "row-style-2"

        total_wallet_value += dict["total_value"]

        print(dict)

    return render_template("home.html", user_cash=cash_value, wallet_list=get_wallet_list, total_value=round(total_wallet_value,2))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        stock_symbol = request.form.get("symbol")
        stock_data = lookup(stock_symbol)
        stock_shares = int(request.form.get("shares"))

        if stock_data == None:
            return apology("invalid symbol", 403)
        elif stock_shares <= 0:
            return apology("invalid shares", 403)

        user_cash = get_user_cash_func(session["user_id"])

        cost = stock_shares * stock_data["price"]

        if user_cash < cost:
            return apology("insufficient funds", 403)

        # record the symbol in our database
        test_symbol_exist = db.execute("SELECT symbol FROM symbols WHERE symbol = ?", stock_data["symbol"])

        if test_symbol_exist == []:
            insert_new_symbol = db.execute("INSERT INTO symbols (symbol) VALUES (?)", stock_data["symbol"])

        get_symbol_id = db.execute("SELECT id FROM symbols WHERE symbol = ?", stock_data['symbol'])

        transaction_time = datetime.now()

        # record a new transaction
        insert_new_transaction = db.execute("INSERT INTO transactions_history (id_symbol, id_user, id_transaction_type, shares, unit_value, transaction_dt) VALUES (?, ?, ?, ?, ?, ?)", get_symbol_id[0]["id"], session["user_id"], PURCHASE_ID[0]["id"], stock_shares, stock_data["price"], transaction_time)

        new_balance = user_cash - cost

        # update user's cash amount in db
        update_user_cash_func(new_balance)

        # update user's wallets

        # check first if the users already have shares from that stock
        test_stock_bought = db.execute("SELECT * FROM wallets WHERE id_symbol = ? AND id_user = ?", get_symbol_id[0]["id"], session["user_id"])

        if test_stock_bought == []:
            insert_new_stock = db.execute("INSERT INTO wallets (id_symbol, id_user, shares) VALUES (?, ?, ?)", get_symbol_id[0]["id"], session["user_id"], stock_shares)
        else:
            owned_shares = test_stock_bought[0]["shares"]
            update_wallet(owned_shares, stock_shares, get_symbol_id[0]["id"])

        #redirect user to homepage
        return redirect("/")

    else:
        return render_template("buy.html")

@app.route("/cash", methods=["GET", "POST"])
@login_required
def cash():

    user_cash = round(get_user_cash_func(session["user_id"]), 2)

    if request.method == "POST":

        cash_action = request.form.get("cash-action")
        cash_amount = int(request.form.get("cash-amount"))

        if cash_action == "withdrawal" and cash_amount > user_cash:

            return apology("not enough funds", 403)

        elif cash_action == "withdrawal" and cash_amount <= user_cash:

            new_balance = user_cash - cash_amount

        elif cash_action == "deposit":

            new_balance = user_cash + cash_amount

        #update_user_cash = db.execute("UPDATE users SET cash = ? WHERE id = ?", new_balance, session["user_id"])
        update_user_cash_func(new_balance)

        #redirect user to homepage
        return redirect("/")

    else:
        return render_template("cash.html", user_cash=user_cash)

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_pwd():

    if request.method == "POST":

        user_actual_pwd = request.form.get("password")
        new_pwd = request.form.get("new-password")
        new_pwd_rpt = request.form.get("new-password-repeat")

        print(user_actual_pwd)
        print(new_pwd)
        print(new_pwd_rpt)

        return redirect("/")

    else:
        return render_template("change-pwd.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    transaction_list = db.execute("SELECT * FROM transactions_history WHERE id_user = ?", session["user_id"])
    row_counter = 0

    def add_data_transaction_list(transaction_dict):

        get_symbol_label = db.execute("SELECT symbol FROM symbols WHERE id = ?", transaction_dict["id_symbol"])
        transaction_dict["label_symbol"] = get_symbol_label[0]["symbol"]

        get_transaction_type = db.execute("SELECT transaction_type FROM transactions_type WHERE id = ?", transaction_dict["id_transaction_type"])
        transaction_dict["transaction_type"] = get_transaction_type[0]["transaction_type"]

    for dict in transaction_list:

        add_data_transaction_list(dict)
        row_counter += 1
        row_even_odd = row_counter % 2

        print(row_counter)
        print(row_even_odd)

        if row_even_odd == 1:
            dict["row_style"] = "row-style-1"
        else:
            dict["row_style"] = "row-style-2"

    return render_template("history.html", transaction_list=transaction_list)


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

        if quote_data == None:
            return apology("invalid symbol", 403)
        else:
            return render_template("quoted.html", quote_data=quote_data)

    elif request.method == "GET":
        return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        password_repeat = request.form.get("password-repeat")

        test_name_exist = db.execute("SELECT username FROM users WHERE username = ?", username)

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


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":

        stock_symbol = request.form.get("symbol")
        stock_data = lookup(stock_symbol)
        stock_shares = int(request.form.get("shares"))
        negative_stock_shares = stock_shares * -1
        get_symbol_id = db.execute("SELECT id FROM symbols WHERE symbol = ?", stock_symbol)
        get_wallet_shares = db.execute("SELECT shares FROM wallets WHERE id_symbol = ? AND id_user = ?", get_symbol_id[0]["id"], session["user_id"])
        transaction_time = datetime.now()
        user_cash = get_user_cash_func(session["user_id"])

        if stock_shares <= 0:
            return apology("invalid shares", 403)
        elif get_wallet_shares[0]["shares"] < stock_shares:
            return apology("not enough shares available to sell", 403)

        # record a new transaction
        insert_new_transaction = db.execute("INSERT INTO transactions_history (id_symbol, id_user, id_transaction_type, shares, unit_value, transaction_dt) VALUES (?, ?, ?, ?, ?, ?)", get_symbol_id[0]["id"], session["user_id"], SALE_ID[0]["id"], negative_stock_shares, stock_data["price"], transaction_time)

        # update wallet
        update_wallet(get_wallet_shares[0]["shares"], negative_stock_shares, get_symbol_id[0]["id"])

        # update user cash
        sale_value = stock_shares * stock_data["price"]
        new_balance = user_cash + sale_value
        update_user_cash_func(new_balance)

        #redirect user to homepage
        return redirect("/")

    elif request.method == "GET":
        get_id_symbols = db.execute("SELECT id_symbol FROM wallets WHERE id_user = ? AND shares > 0", session["user_id"])
        symbols_list = []

        for dict in get_id_symbols:
            get_symbol_label = db.execute("SELECT symbol FROM symbols WHERE id = ?", dict["id_symbol"])
            symbols_list.append(get_symbol_label[0]["symbol"])

        return render_template("sell.html", symbol_select = sorted(symbols_list))


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
