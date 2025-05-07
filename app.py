from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import os
import uuid
import json
from encryption_tool import encrypt_file, decrypt_file  
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
UPLOAD_FOLDER = 'uploads'
RESULT_FOLDER = 'results'
USERS_FILE = 'users.json'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULT_FOLDER, exist_ok=True)

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users = load_users()
        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('home'))  # Redirect to home after successful login
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm_password']
        users = load_users()
        if username in users:
            flash('Username already exists.', 'danger')
        elif password != confirm:
            flash('Passwords do not match.', 'danger')
        else:
            users[username] = password
            save_users(users)
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))  # Redirect to login after successful registration
    return render_template('register.html')

@app.route('/process', methods=['POST'])
def process_file():
    if 'username' not in session:
        return redirect(url_for('login'))

    file = request.files['file']
    key = request.form['key']
    algorithm = request.form['algorithm']
    action = request.form['action']

    if file and key:
        filename = secure_filename(file.filename)
        original_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(original_path)

        if action == 'encrypt':
            output_filename = filename + '.enc'
            output_path = os.path.join(RESULT_FOLDER, output_filename)
            encrypt_file(original_path, output_path, key, algorithm)
        elif action == 'decrypt':
            output_filename = filename.rsplit('.enc', 1)[0]
            output_path = os.path.join(RESULT_FOLDER, output_filename)
            try:
                decrypt_file(original_path, output_path, key, algorithm)
            except Exception:
                return render_template('result.html', error='Decryption failed. Ensure the key and algorithm are correct.')
        else:
            return render_template('result.html', error='Invalid action.')

        return render_template('result.html', download_link=url_for('download_file', filename=os.path.basename(output_path)))
    else:
        return render_template('result.html', error='Missing file or key.')

@app.route('/download/<filename>')
def download_file(filename):
    return send_file(os.path.join(RESULT_FOLDER, filename), as_attachment=True)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)