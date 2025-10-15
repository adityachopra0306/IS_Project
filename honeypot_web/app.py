import os
import logging
from flask import Flask, request, render_template_string, g
import pymysql

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)

DB_HOST = os.getenv("DB_HOST", "mysql_db")
DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASS", "password")
DB_NAME = os.getenv("DB_NAME", "vulndb")

BANNER = os.getenv("BANNER", "Welcome to AASS Web Honeypot")

INDEX_HTML = """
<!doctype html>
<title>{{banner}}</title>
<h1>{{banner}}</h1>
<p>Try: <a href="/search?query=test">/search?query=...</a> or <a href="/greet?name=Bob">/greet?name=...</a></p>
<form action="/login" method="POST">
  <input name="username" placeholder="username"><input name="password" placeholder="password" type="password">
  <button>Login</button>
</form>
"""

def get_db():
    if 'db' not in g:
        g.db = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, db=DB_NAME, cursorclass=pymysql.cursors.DictCursor)
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.route('/')
def index():
    return render_template_string(INDEX_HTML, banner=BANNER)

# Vulnerable to SQL injection: uses string formatting directly
@app.route('/search')
def search():
    q = request.args.get('query', '')
    src = request.remote_addr
    app.logger.info(f"HONEYPOT_SEARCH src={src} query={q} ua={request.headers.get('User-Agent')}")
    db = get_db()
    with db.cursor() as cur:
        # INTENTIONAL VULN: do not use parameterized queries in honeypot
        sql = f"SELECT id, title, content FROM articles WHERE title LIKE '%{q}%' LIMIT 10;"
        cur.execute(sql)
        rows = cur.fetchall()
    return {"results": rows}

# Reflected XSS (renders input unsanitized)
@app.route('/greet')
def greet():
    name = request.args.get('name', 'friend')
    src = request.remote_addr
    app.logger.info(f"HONEYPOT_GREET src={src} name={name} ua={request.headers.get('User-Agent')}")
    # INTENTIONAL: reflect directly (vulnerable)
    html = f"<h2>Hello, {name}!</h2>"
    return html

# Fake login that just logs creds (useful for brute force capture)
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username','')
    password = request.form.get('password','')
    src = request.remote_addr
    ts = __import__('datetime').datetime.utcnow().isoformat()+"Z"
    app.logger.info(f"HONEYPOT_LOGIN src={src} user={username!r} pass={password!r} ts={ts} ua={request.headers.get('User-Agent')}")
    # Always fail to encourage retries (or you can sometimes succeed to capture post-exploit behavior)
    return "Login failed", 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)