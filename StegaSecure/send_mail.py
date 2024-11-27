from flask import Flask
from flask_mail import Mail, Message
app = Flask(__name__)

# Flask-Mail setup
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'  # Use your SMTP server here (e.g., Gmail, SendGrid)
app.config['MAIL_PORT'] =  587  # Port for SSL
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'manalip2134@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = ' iqjr gwwx lwod fwkp'  # Replace with your email password or app password mail :mywb mftj pvip lxrj
app.config['MAIL_DEFAULT_SENDER'] = 'manalip2134@gmail.com'  # Replace with your email

mail = Mail(app)
mail.init_app(app)
def send_otp_email(user_email, otp):
    """Send the OTP code to the user's email."""
    msg = Message('Your One-Time Authentication Code', recipients=[user_email])
    msg.body = f"Your one-time authentication code is: {otp}"
    try:
        email='drishtimane229@gmail.com'
        mail.send(msg)
        print(f"OTP sent to {user_email}")
    except Exception as e:
        print(f"Failed to send OTP: {str(e)}")  # Catch any errors and print them


# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
