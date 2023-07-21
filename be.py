from flask import Flask, request, jsonify, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import pymongo
from flask_mongoengine import MongoEngine
import jwt
import datetime
from functools import wraps
import base64
from flask_mail import Mail, Message
from random import randint

app = Flask(__name__)
app.config["MONGODB_HOST"] = "mongodb+srv://ren1:test1@rent1.r0twrgt.mongodb.net/MDB"
app.config['SECRET_KEY'] = 'gigaSecRETKeythATnoOnecAnFinDD'
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'renmailtester@gmail.com'
app.config['MAIL_PASSWORD'] = 'uzamscmcgpwskwod'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True


db = MongoEngine()
db.init_app(app)
mail = Mail(app)

class account(db.Document):
    email = db.StringField(required=True, unique=True)
    name = db.StringField(required=True)
    password = db.StringField(required=True)
    list_of_devices = db.ListField(db.IntField())
    active = db.BooleanField(default=False)
    reset_code = db.IntField()

    def set_email(self, email):
        self.email = base64.b64encode(email.encode()).decode()  # Encode to base64

    def get_email(self):
        return base64.b64decode(self.email.encode()).decode()  # Decode from base64

    def set_name(self, name):
        self.name = base64.b64encode(name.encode()).decode()  # Encode to base64

    def get_name(self):
        return base64.b64decode(self.name.encode()).decode()  # Decode from base64

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

def send_confirmation_email(user_email):
    token = jwt.encode({'email': user_email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")
    msg = Message('Confirm Email', sender = 'yourtestmail@gmail.com', recipients = [user_email])
    link = url_for('confirm_email', token=token, _external=True)
    msg.body = 'Your link is {}'.format(link)
    mail.send(msg)

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = base64.b64encode(data['email'].encode()).decode()
    name = base64.b64encode(data['name'].encode()).decode()
    password = data['password']
    devices = data.get('devices', []) 

    existing_user = account.objects(email=email).first()
    if existing_user is not None:
        return jsonify({"error": "A user with this email already exists"}), 400

    user = account(name=name, email=email, password=generate_password_hash(password, method='sha256'), list_of_devices=devices, active=False)
    user.save()

    send_confirmation_email(data['email'])

    return jsonify({'message': 'Successfully signed up for Todo, please confirm your email before login'}), 200


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = account.objects(email=base64.b64encode(data['email'].encode()).decode()).first()
    if user and user.check_password(data['password']):
        if user.active:
            token = jwt.encode({'username': user.get_name(), 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")
            return jsonify({'token': token})
        else:
            return jsonify({'message': 'Account not active. Please confirm your email.'}), 403
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/confirm_email/<token>', methods=['GET'])
def confirm_email(token):
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        user_email = data['email']
        user = account.objects(email=base64.b64encode(user_email.encode()).decode()).first()
        if user:
            user.active = True
            user.save()
            return jsonify({'message': 'The email is confirmed.'}), 200
        else:
            return jsonify({'message': 'User not found.'}), 404
    except:
        return jsonify({'message': 'The confirmation link is invalid or has expired.'}), 400


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            token = auth_header.split(" ")[1]  # split on space and take the second element.


        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            username_encoded = base64.b64encode(data['username'].encode()).decode()  # Encode username to base64
            current_user = account.objects(name=username_encoded).first()
            if current_user is None:
                raise Exception('User not found')
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

def send_reset_password_email(user_email, code):
    msg = Message('Reset Password', sender = 'yourtestmail@gmail.com', recipients = [user_email])
    msg.body = 'Your reset code is {}'.format(code)
    mail.send(msg)

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    user = account.objects(email=base64.b64encode(data['email'].encode()).decode()).first()
    if user is None:
        return jsonify({'message': 'Email not found'}), 404

    code = randint(10000000, 99999999)
    user.reset_code = code
    user.save()

    send_reset_password_email(data['email'], code)

    return jsonify({'message': 'A reset code has been sent to your email'}), 200

@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email_encoded = base64.b64encode(data['email'].encode()).decode()
    user = account.objects(email=email_encoded, reset_code=data['code']).first()

    if user is None:
        return jsonify({'message': 'Invalid reset code or email'}), 400

    user.set_password(data['password'])
    user.reset_code = None
    user.save()

    return jsonify({'message': 'Your password has been reset'}), 200


@app.route('/get_devices', methods=['GET'])
@token_required
def get_devices(current_user):
    return jsonify({'devices': current_user.list_of_devices}), 200


if __name__=='__main__':
    app.run(host='0.0.0.0',port=2999)
