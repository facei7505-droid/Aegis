"""VulnShop - a deliberately vulnerable web shop used to demonstrate Aegis.

!!! DO NOT DEPLOY. Every endpoint here contains a real, classic vulnerability on
purpose. It is meant to run only on localhost / inside tests. !!!
"""
import base64
import hashlib
import os
import pickle
import sqlite3
import subprocess
import sys

from flask import Flask, make_response, render_template_string, request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("VULNSHOP_DB", os.path.join(BASE_DIR, "shop.db"))
FILES_DIR = os.path.join(BASE_DIR, "files")
NETCHECK = os.path.join(BASE_DIR, "tools", "netcheck.py")

app = Flask(__name__)
app.secret_key = "sk_live_9f8e7d6c5b4a3f2e1d0c"


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, role TEXT);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price INTEGER);
        """
    )
    admin_hash = hashlib.md5(b"correct-horse-battery").hexdigest()
    conn.execute("INSERT INTO users (username, password_hash, role) VALUES ('admin', ?, 'admin')", (admin_hash,))
    conn.executemany(
        "INSERT INTO products (name, price) VALUES (?, ?)",
        [("Laptop", 450000), ("Phone", 210000), ("Headphones", 35000), ("O'Brien Mug", 4000)],
    )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return ("<h1>VulnShop</h1><p>A deliberately vulnerable shop for the Aegis demo.</p><ul>"
            "<li><a href='/search?q=laptop'>/search?q=laptop</a></li><li><a href='/greet?name=Aigerim'>/greet</a></li>"
            "<li><a href='/download?file=readme.txt'>/download?file=readme.txt</a></li>"
            "<li><a href='/ping?host=127.0.0.1'>/ping?host=127.0.0.1</a></li>"
            "<li><a href='/products?filter=price%3C100000'>/products</a></li></ul>")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    pw_hash = hashlib.md5(password.encode()).hexdigest()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{pw_hash}'"
    user = db().execute(query).fetchone()
    if user:
        return f"Welcome {user['username']} (role: {user['role']})"
    return "Invalid credentials", 401


@app.route("/search")
def search():
    q = request.args.get("q", "")
    rows = db().execute(f"SELECT name, price FROM products WHERE name LIKE '%{q}%'").fetchall()
    items = "".join(f"<li>{r['name']} - {r['price']} KZT</li>" for r in rows)
    return f"<h1>Results for {q}</h1><ul>{items}</ul>"


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.run(f'"{sys.executable}" "{NETCHECK}" {host}', shell=True, capture_output=True, text=True)
    return f"<pre>{result.stdout}</pre>"


@app.route("/download")
def download():
    name = request.args.get("file", "readme.txt")
    try:
        with open(f"{FILES_DIR}/{name}") as fh:
            return fh.read()
    except FileNotFoundError:
        return "file not found", 404


@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    return render_template_string(f"<p>Hello {name}!</p>")


@app.route("/products")
def products():
    raw = request.args.get("filter", "{}")
    try:
        flt = eval(raw)
    except Exception:
        return "bad filter", 400
    limit = flt.get("max_price", 10**9) if isinstance(flt, dict) else 10**9
    rows = db().execute("SELECT name, price FROM products").fetchall()
    return f"filter={flt!r} -> " + ", ".join(r["name"] for r in rows if r["price"] <= limit)


@app.route("/cart")
def cart():
    raw = request.cookies.get("cart")
    items = pickle.loads(base64.b64decode(raw)) if raw else []
    return make_response(f"{len(items)} item(s) in cart")


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
