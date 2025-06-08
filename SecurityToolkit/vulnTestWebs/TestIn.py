from flask import Flask, request, render_template_string

app = Flask(__name__)

# Simulating a user database
users = {
    "1": {"name": "Alice"},
    "2": {"name": "Bob"},
    "3": {"name": "Charlie"}
}

@app.route("/")
def index():
    id_param = request.args.get("id")
    search_param = request.args.get("search")

    # SQLi vulnerable (simulation)
    if id_param:
        try:
            # Simulating insecure SQL query
            if "'" in id_param or "--" in id_param or "OR" in id_param.upper():
                raise Exception("SQL syntax error")
            user = users.get(id_param, {"name": "Unknown"})
            return f"<h2>Welcome, {user['name']}</h2>"
        except Exception as e:
            return f"<h2>Error: {e}</h2>"

    # XSS vulnerable (simulation)
    if search_param:
        html_response = f"<h2>Search results for: {search_param}</h2>"
        return render_template_string(html_response)

    return '''
        <h1>Vulnerable Flask App</h1>
        <p>Use <code>?id=</code> for SQLi test</p>
        <p>Use <code>?search=</code> for XSS test</p>
    '''

if __name__ == "__main__":
    app.run(debug=True)