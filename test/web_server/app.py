from flask import Flask, render_template, request

app = Flask(__name__)

# Hardcoded credentials for testing the packet sniffer
VALID_USER = "admin"
VALID_PASS = "supersecret"

@app.route('/')
def login_page():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    # Extracting cleartext data from the POST request
    username = request.form.get('username')
    password = request.form.get('password')

    if username == VALID_USER and password == VALID_PASS:
        return render_template('success.html', username=username)
    else:
        return render_template('error.html')

if __name__ == '__main__':
    # host='0.0.0.0' allows external connections across your virtual network
    app.run(host='0.0.0.0', port=8080, debug=True)
