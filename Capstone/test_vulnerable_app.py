"""
=============================================================================
LOCAL VULNERABLE TEST BENCH APPLICATION (FOR COLLEGE CAPSTONE DEMONSTRATION)
=============================================================================
This application provides an authorized, safe, local demonstration target
specifically configured to showcase:
1. Missing Security Headers (CSP, HSTS, X-Frame-Options)
2. Server Version Information Disclosure banner
3. Reflected Cross-Site Scripting (XSS) on /search and /feedback
4. Unhandled Database SQL Syntax Error on /products?category=
=============================================================================
"""

import os
import sqlite3
from flask import Flask, request, Response, render_template_string

test_app = Flask(__name__)
DB_FILE = os.path.join(os.path.dirname(__file__), "test_lab.db")

def init_lab_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("CREATE TABLE IF NOT EXISTS items (id INTEGER, name TEXT, category TEXT, price REAL)")
    conn.execute("DELETE FROM items")
    conn.execute("INSERT INTO items VALUES (1, 'Wireless Mouse', 'electronics', 25.0)")
    conn.execute("INSERT INTO items VALUES (2, 'Mechanical Keyboard', 'electronics', 75.0)")
    conn.execute("INSERT INTO items VALUES (3, 'Security Handbook', 'books', 40.0)")
    conn.commit()
    conn.close()

init_lab_db()

def get_db():
    return sqlite3.connect(DB_FILE)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>VulnLab Test Application (Authorized Demonstration Target)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f4f6f8; color: #333; }
        .box { background: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        input[type=text] { width: 300px; padding: 8px; margin: 5px 0; }
        button { padding: 8px 16px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="box">
        <h2>Target Demonstration Web Application (Port 5050)</h2>
        <p>This application is intentionally configured for testing vulnerability scanners safely in a local sandbox.</p>
    </div>

    <!-- Vulnerable Search Form (Reflected XSS) -->
    <div class="box">
        <h3>1. Product Search (Reflected Parameter)</h3>
        <form action="/search" method="GET">
            <label>Search keyword:</label><br/>
            <input type="text" name="query" value="{{ query|default('') }}"><br/>
            <button type="submit">Search</button>
        </form>
        {% if query %}
            <div style="margin-top: 15px; padding: 10px; background: #e8f4fd;">
                <!-- VULNERABILITY: Raw unescaped reflection -->
                Results for search term: {{ query | safe }}
            </div>
        {% endif %}
    </div>

    <!-- Vulnerable Category Filter (SQL Injection Error) -->
    <div class="box">
        <h3>2. Filter Products by Category (SQL Injection Trigger)</h3>
        <p>Quick links: <a href="/products?category=electronics">Electronics</a> | <a href="/products?category=books">Books</a></p>
        <form action="/products" method="GET">
            <label>Category parameter:</label><br/>
            <input type="text" name="category" value="{{ category|default('') }}"><br/>
            <button type="submit">Filter Query</button>
        </form>
        {% if error_msg %}
            <div style="margin-top: 15px; padding: 10px; background: #fde8e8; color: #c00;">
                <b>Database Query Error:</b> {{ error_msg }}
            </div>
        {% endif %}
        {% if items %}
            <ul>
                {% for item in items %}
                    <li>{{ item[1] }} - ${{ item[3] }}</li>
                {% endfor %}
            </ul>
        {% endif %}
    </div>

    <!-- Feedback Form (Form-based XSS) -->
    <div class="box">
        <h3>3. Submit Feedback</h3>
        <form action="/feedback" method="POST">
            <label>Your Name:</label><br/>
            <input type="text" name="name"><br/>
            <label>Comments:</label><br/>
            <input type="text" name="comment"><br/>
            <button type="submit">Submit Feedback</button>
        </form>
        {% if feedback_msg %}
            <div style="margin-top: 15px; padding: 10px; background: #eef;">
                Thank you: {{ feedback_msg | safe }}
            </div>
        {% endif %}
    </div>
</body>
</html>
"""

@test_app.route('/')
def home():
    resp = Response(render_template_string(HTML_TEMPLATE), mimetype='text/html')
    resp.headers['Server'] = 'Apache-Test-Bench/2.4.41 (Ubuntu)'
    resp.headers['X-Powered-By'] = 'PHP/7.4.3-DevLab'
    return resp

@test_app.route('/search')
def search():
    query = request.args.get('query', '')
    resp = Response(render_template_string(HTML_TEMPLATE, query=query), mimetype='text/html')
    resp.headers['Server'] = 'Apache-Test-Bench/2.4.41 (Ubuntu)'
    return resp

@test_app.route('/products')
def products():
    category = request.args.get('category', '')
    items = []
    error_msg = None

    if category:
        conn = get_db()
        try:
            sql = f"SELECT * FROM items WHERE category = '{category}'"
            cursor = conn.cursor()
            cursor.execute(sql)
            items = cursor.fetchall()
        except sqlite3.OperationalError as e:
            error_msg = f"sqlite_error: near unrecognized token in SQL query: {str(e)}"
        finally:
            conn.close()

    resp = Response(render_template_string(HTML_TEMPLATE, category=category, items=items, error_msg=error_msg), mimetype='text/html')
    resp.headers['Server'] = 'Apache-Test-Bench/2.4.41 (Ubuntu)'
    return resp

@test_app.route('/feedback', methods=['POST'])
def feedback():
    name = request.form.get('name', '')
    comment = request.form.get('comment', '')
    msg = f"{name} ({comment})"
    resp = Response(render_template_string(HTML_TEMPLATE, feedback_msg=msg), mimetype='text/html')
    resp.headers['Server'] = 'Apache-Test-Bench/2.4.41 (Ubuntu)'
    return resp

if __name__ == '__main__':
    print("Test bench running on http://127.0.0.1:5050")
    test_app.run(host='127.0.0.1', port=5050, debug=False)
