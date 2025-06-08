from flask import Flask, request, render_template_string, session, jsonify
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your-secure-key-12345'

# Enhanced login page with more attack vectors
LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Test Portal</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .alert { color: red; padding: 10px; margin: 10px 0; border: 1px solid red; }
        form { max-width: 400px; }
        input { margin: 5px 0; width: 100%; }
    </style>
</head>
<body>
    <h1>Login Test Page</h1>
    <form method="POST" action="/login">
        <label>Username:</label>
        <input type="text" name="username" required>
        
        <label>Password:</label>
        <input type="password" name="password" required>
        
        <button type="submit">Login</button>
    </form>
    
    {% if message %}
    <div class="alert">{{ message }}</div>
    {% endif %}
    
    {% if locked %}
    <div class="alert">Account locked for {{ remaining_time }} seconds</div>
    {% endif %}
    
    <hr>
    <h2>Test Endpoints</h2>
    <ul>
        <li><a href="/sqli?id=1">SQLi Test (id=1)</a></li>
        <li><a href="/xss?search=test">XSS Test (search=test)</a></li>
    </ul>
</body>
</html>
"""

# Valid credentials
VALID_USERS = {
    "admin": "admin123",
    "tester": "test123"
}

@app.route("/")
def index():
    return render_template_string(LOGIN_PAGE)

@app.route("/login", methods=["POST"])
def login():
    # Security settings
    MAX_ATTEMPTS = 3
    LOCKOUT_MINUTES = 5
    
    # Initialize counters
    if 'attempts' not in session:
        session['attempts'] = 0
        session['locked_until'] = None
    
    message = ""
    locked = False
    remaining_time = 0
    
    # Check lock status
    if session.get('locked_until'):
        lock_time = datetime.strptime(session['locked_until'], '%Y-%m-%d %H:%M:%S')
        if datetime.now() < lock_time:
            locked = True
            remaining_time = (lock_time - datetime.now()).seconds
    
    # Process login attempt
    if not locked:
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        
        # Log the attempt (for testing detection)
        print(f"Login attempt: {username}/{password}")
        
        if username in VALID_USERS and VALID_USERS[username] == password:
            message = "Login successful!"
            session['attempts'] = 0  # Reset on success
        else:
            session['attempts'] += 1
            message = f"Invalid credentials (attempt {session['attempts']}/{MAX_ATTEMPTS})"
            
            # Trigger lockout
            if session['attempts'] >= MAX_ATTEMPTS:
                lock_time = datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)
                session['locked_until'] = lock_time.strftime('%Y-%m-%d %H:%M:%S')
                locked = True
                remaining_time = LOCKOUT_MINUTES * 60
                message = f"Account locked for {LOCKOUT_MINUTES} minutes"

    return render_template_string(LOGIN_PAGE,
                               message=message,
                               locked=locked,
                               remaining_time=remaining_time)

# SQLi vulnerable endpoint
@app.route("/sqli")
def sqli_test():
    user_id = request.args.get("id", "1")
    
    # Simulate SQL injection vulnerability
    try:
        if any(keyword in user_id.lower() for keyword in ["'", "--", "or ", "1=1"]):
            raise Exception("SQL syntax error near: " + user_id[:20])
        
        return f"<h2>User Info for ID: {user_id}</h2><p>Name: Test User</p>"
    except Exception as e:
        return f"<h2>Error: {str(e)}</h2>"

# XSS vulnerable endpoint
@app.route("/xss")
def xss_test():
    search_term = request.args.get("search", "")
    return f"<h2>Search Results</h2><p>You searched for: {search_term}</p>"

if __name__ == "__main__":
    print("\n[+] Starting Security Test Server on port 5000")
    print("[+] Access at: http://localhost:5000")
    print("[+] Test endpoints:")
    print("    - /login (Brute Force)")
    print("    - /sqli?id=1 (SQLi)")
    print("    - /xss?search=test (XSS)")
    print("[+] Valid credentials:")
    for user in VALID_USERS:
        print(f"    Username: {user} | Password: {VALID_USERS[user]}")
    print("[+] Server will lock after 3 failed attempts\n")
    
    try:
        app.run(host="127.0.0.1", port=5000, debug=False)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")