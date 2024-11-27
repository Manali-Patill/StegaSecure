from flask import Flask, request, jsonify, render_template, session, redirect, url_for, g
import bcrypt
import pyotp
import qrcode
from flask_mail import Mail, Message
import secrets
from io import BytesIO
from base64 import b64encode
from PIL import Image
import sqlite3

import concurrent.futures


# Flask app configuration
app = Flask(__name__)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'your_mail@gmail.com'
app.config['MAIL_PASSWORD'] = 'your password here'  # Use app password here, not Gmail password
app.config['MAIL_DEFAULT_SENDER'] = 'your_mail@gmail.com'
app.secret_key = secrets.token_hex(16)  # Secure random secret key for session management

# Flask-Mail initialization
mail = Mail(app)
mail.init_app(app)

DATABASE = 'your_database_file.db'  # Path to your database

# Database helper functions
def get_db():
    """Connect to the database."""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(error=None):
    """Close the database connection."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Helper function to generate TOTP QR code
def generate_totp_qr_code(email, totp_secret):
    """Generate a QR code for the TOTP secret."""
    totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(name=email, issuer_name="StegaSecure")
    qr = qrcode.QRCode(box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    
    # Convert image to base64 for embedding in HTML
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return b64encode(buffered.getvalue()).decode()

# Route to serve the signup page
@app.route('/')
def index():
    """Render the signup form page."""
    return render_template('signup.html')
from PIL import Image
import io

def encode_secret_in_image(image_path, secret_code):
    """Encode the secret code into the image using steganography."""
    # Open the image
    img = Image.open(image_path)
    img = img.convert('RGB')  # Ensure the image is in RGB format
    
    # Convert secret code to binary
    binary_message = ''.join(format(ord(char), '08b') for char in secret_code)
    binary_message += '1111111111111110'  # Add a delimiter for the end of the message

    # Modify the image pixels to encode the secret message
    pixels = img.load()
    data_index = 0
    for row in range(img.height):
        for col in range(img.width):
            if data_index < len(binary_message):
                pixel = list(pixels[col, row])
                for i in range(3):  # Modify RGB values
                    if data_index < len(binary_message):
                        pixel[i] = pixel[i] & 0xFE | int(binary_message[data_index])
                        data_index += 1
                pixels[col, row] = tuple(pixel)
            else:
                break

    # Save the image with the secret encoded
    encoded_image_path = "uploads/encoded_" + image_path.split("/")[-1]
    img.save(encoded_image_path)
    return encoded_image_path


@app.route('/signup', methods=['POST'])
def signup():
    """Handle the form submission and save user to the database."""
    data = request.form
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    secret_code = data.get('secret_code')

    # Validate inputs
    if not username or not email or not password or not secret_code:
        return jsonify({'error': 'All fields are required'}), 400

    # Handle image upload
    image = request.files.get('image')
    if not image:
        return jsonify({'error': 'Image file is required'}), 400

    # Save the image temporarily
    image_path = f"uploads/{image.filename}"
    image.save(image_path)

    # Encode the secret code into the uploaded image
    encoded_image_path = encode_secret_in_image(image_path, secret_code)

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Generate a unique TOTP secret
    totp_secret = pyotp.random_base32()
    qr_code = generate_totp_qr_code(email, totp_secret)

    # Save user in the database
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(
            'INSERT INTO users (username, email, password_hash, secret_code, totp_secret, encoded_image) VALUES (?, ?, ?, ?, ?, ?)',
            (username, email, hashed_password, secret_code, totp_secret, encoded_image_path)
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email already exists'}), 400

    return render_template('signup_success.html', qr_code=qr_code)


# Route to handle login
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle the login form submission and authenticate the user."""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            return jsonify({'error': 'Both email and password are required'}), 400

        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({'error': 'Invalid email or password'}), 400

        stored_password_hash = user['password_hash']

        if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash):
            # Set session variables
            session['user_id'] = user['id']
            session['username'] = user['username']

            # Send OTP email
            return redirect(url_for('send_otp_email'))
        else:
            return jsonify({'error': 'Invalid email or password'}), 400

    return render_template('login.html')

@app.route('/send_otp', methods=['GET'])
def send_otp_email():
    """Generate and send OTP via email."""
    # Get the database connection
    db = get_db()
    cursor = db.cursor()

    # Get user details based on session's user_id
    cursor.execute('SELECT totp_secret, email FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()

    # If the user is not found in the database, return an error
    if not user:
        return jsonify({'error': 'User not found'}), 400

    totp_secret = user['totp_secret']
    email = user['email']
    
    # Generate OTP using the TOTP secret
    totp = pyotp.TOTP(totp_secret)
    otp = totp.now()

    # Store the OTP in the session for later verification
    session['otp'] = otp

    # Create and send the OTP email
    msg = Message('Your One-Time Authentication Code', recipients=[email])
    msg.body = f"Your one-time authentication code is: {otp}"

    try:
        mail.send(msg)
        print(f"Sent OTP: {otp} to {email}")  # Debugging line to ensure OTP is being sent

        # Redirect to OTP verification page
        return redirect(url_for('verify_otp'))
    except Exception as e:
        # If sending fails, return an error
        return jsonify({'error': f'Failed to send OTP: {str(e)}'}), 500

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        stored_otp = session.get('otp')

        # Check if OTP is available in session
        if not stored_otp:
            return jsonify({'error': 'OTP not generated or expired'}), 400

        # Validate the entered OTP against the stored OTP
        if entered_otp != stored_otp:
            return jsonify({'error': 'Invalid or expired OTP'}), 400

        # OTP is valid, proceed to next step (e.g., redirect to steganography authentication)
        session.pop('otp', None)  # Clear OTP from session after successful verification
        return redirect(url_for('stego_auth'))  # Redirect to steganography authentication page

    return render_template('verify_otp.html')  # Ensure you have a separate template for OTP verification

# Steganography authentication
from flask import request, jsonify


@app.route('/stego_auth', methods=['GET', 'POST'])
def stego_auth():
    """Handle steganography-based authentication."""
    if request.method == 'POST':
        uploaded_file = request.files.get('stegano_image')
        
        if not uploaded_file:
            return jsonify({'error': 'No file uploaded'}), 400
        
        # Debug: check file info
        print(f"Uploaded file: {uploaded_file.filename}")
        print(f"File content type: {uploaded_file.content_type}")
        
        try:
            # Save the uploaded file temporarily
            file_path = f"uploads/{uploaded_file.filename}"
            uploaded_file.save(file_path)
            print(f"File saved at: {file_path}")
            
            # Proceed with decoding
            decoded_message = decode_message(file_path)
            
            expected_message = session.get('secret_code')
            if decoded_message == expected_message:
                return redirect(url_for('dashboard'))
        #     else:
        #         return jsonify({'error': 'Invalid steganography authentication.'}), 400
        except Exception as e:
            return jsonify({'error': f'Error processing the image: {str(e)}'}), 500

    return render_template('stego_auth.html')  # Ensure this template exists


def decode_message(image_path):
    """Decode the hidden message from the image using steganography."""
    # Open the image
    img = Image.open(image_path)
    img = img.convert('RGB')  # Ensure the image is in RGB format

    # Extract the binary data from the image
    binary_message = ""
    pixels = img.load()
    
    for row in range(img.height):
        for col in range(img.width):
            pixel = pixels[col, row]
            for i in range(3):  # Read from RGB channels
                binary_message += str(pixel[i] & 1)  # Extract the least significant bit

    # Split the binary message into 8-bit chunks
    byte_message = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]

    # Convert binary chunks to characters until the delimiter is reached
    decoded_message = ""
    for byte in byte_message:
        if byte == '11111110':  # Check for the delimiter
            break
        decoded_message += chr(int(byte, 2))

    return decoded_message




@app.route('/dashboard')
def dashboard():
    """Render the dashboard page if the user is logged in."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    username = session['username']
    return render_template('index.html', username=username)

@app.route('/logout')
def logout():
    """Handle logging out a user."""
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.teardown_appcontext
def teardown(exception):
    """Close the database connection after each request."""
    close_db()

if __name__ == '__main__':
    app.run(debug=True)
