import sqlite3
import pickle
import pandas as pd
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import os
from sklearn.preprocessing import LabelEncoder, StandardScaler
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Define feature columns
FEATURE_COLUMNS = [
    'PROTOCOL_MAP', 'L4_SRC_PORT', 'L4_DST_PORT', 
    'FLOW_DURATION_MILLISECONDS', 'PROTOCOL', 
    'TCP_FLAGS', 'TCP_WIN_MAX_IN', 'TCP_WIN_MAX_OUT', 
    'TCP_WIN_MIN_IN', 'TCP_WIN_MIN_OUT', 'TCP_WIN_MSS_IN', 
    'TCP_WIN_SCALE_IN', 'TOTAL_FLOWS_EXP', 'IN_BYTES', 
    'IN_PKTS', 'OUT_BYTES', 'OUT_PKTS', 'ANALYSIS_TIMESTAMP',
    'FIRST_SWITCHED', 'LAST_SWITCHED'
]

# Model and Scaler paths
MODEL_PATH = 'MLModels/random_forest_model.pkl'
SCALER_PATH = 'MLModels/scaler.pkl'

# Load Model and Scaler
model = pickle.load(open(MODEL_PATH, 'rb')) if os.path.exists(MODEL_PATH) else None
scaler = pickle.load(open(SCALER_PATH, 'rb')) if os.path.exists(SCALER_PATH) else None

# Database initialization
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Call to initialize database
init_db()

# Preprocessing Function
def preprocess_data(df):
    # Encode categorical columns
    if 'PROTOCOL_MAP' in df.columns:
        le = LabelEncoder()
        df['PROTOCOL_MAP'] = le.fit_transform(df['PROTOCOL_MAP'].astype(str))

    # Drop irrelevant columns
    columns_to_drop = ['ANOMALY', 'ALERT', 'ID', 'IPV4_SRC_ADDR', 'IPV4_DST_ADDR']
    df.drop(columns=columns_to_drop, axis=1, errors='ignore', inplace=True)

    # Ensure all expected columns exist
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0

    # Reorder columns to match training
    df = df[FEATURE_COLUMNS]

    # Standardize features using pre-trained scaler
    scaled_features = scaler.transform(df) if scaler else df
    return scaled_features

# Prediction Function
def predict_packets(data):
    if not model:
        raise ValueError("Random Forest model is not available.")
    return model.predict(data)

# Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return 'Username already exists!'

    return render_template('signup.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[0], password):
            session['user_id'] = username
            return redirect(url_for('index'))
        return 'Invalid username or password!'

    return render_template('login.html')

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# Upload and Prediction Route
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in ['.csv']:
        return jsonify({'error': 'Invalid file format'}), 400

    try:
        df = pd.read_csv(file)
        print(f"Uploaded Data Shape: {df.shape}")
        data = preprocess_data(df)

        predictions = predict_packets(data)
        df['Prediction'] = predictions
        df['Prediction'] = df['Prediction'].map({0: 'Benign', 1: 'Malicious'})

        benign_count = (df['Prediction'] == 'Benign').sum()
        malicious_count = (df['Prediction'] == 'Malicious').sum()

        results = {
            'Model': 'random_forest',
            'Benign Count': int(benign_count),
            'Malicious Count': int(malicious_count),
            'Predictions': df.to_dict(orient='records')
        }

        # Print results in the terminal
        print(f"Results Summary: Benign - {benign_count}, Malicious - {malicious_count}")
        print("Detailed Predictions:")
        print(df.head(10))

        return render_template('result_pages.html', results=results)

    except ValueError as ve:
        return jsonify({'error': str(ve)}), 500
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500

# Home Route
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', models=['random_forest'])

if __name__ == '__main__':
    app.run(debug=True)
