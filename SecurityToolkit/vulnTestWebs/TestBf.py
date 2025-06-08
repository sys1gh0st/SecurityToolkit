from flask import Flask, request, render_template_string

app = Flask(__name__)

# Login page
LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h1>Login</h1>
    <form method="POST">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br><br>
        <button type="submit">Login</button>
    </form>
    <p>{{ message }}</p>
</body>
</html>
"""

# Valid credentials
users = {
    "1": {"name": "Alice"},
    "2": {"name": "Bob"},
    "3": {"name": "Charlie"}
}
VALID_USERNAME = "admin"
VALID_PASSWORD = "password"

@app.route("/", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == VALID_USERNAME and password == VALID_PASSWORD:
            message = "Login successful!"
        else:
            message = "Invalid username or password."

    return render_template_string(LOGIN_PAGE, message=message)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)