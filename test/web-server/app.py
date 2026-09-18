from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

VALID_USER = "admin"
VALID_PASS = "supersecret"

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy"}), 200

@app.route('/')
def login_page():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if username == VALID_USER and password == VALID_PASS:
        return render_template('success.html', username=username)
    else:
        return render_template('error.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
