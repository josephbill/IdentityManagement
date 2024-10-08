from flask import Flask, jsonify, request
# handle migrations 
from flask_migrate import Migrate
from datetime import datetime, timedelta
#import models 
from models.passwordresettoken import PasswordResetToken
from models.user import User
from models.dbconfig import db 
# encryption
from werkzeug.security import generate_password_hash, check_password_hash
# documentation : Swagger : pip install flasgger
from flasgger import Swagger
# generation token 
import random 
import string
import base64
# protection of routes using JWT : pip install jwt 
import jwt
import os 
# file uploads pip install cloudinary
import cloudinary
import cloudinary.uploader

app = Flask(__name__)
app.config['SWAGGER'] = {
    'title' : 'Auth and Cloudinary APIs',
    'uiversion' : 3 
}

swagger = Swagger(app)
# config db 
app.config['SQLALCHEMY_DATABASE_URI']  =  'sqlite:///app.db'
db.init_app(app)
# initialize flask migrate 
migrate = Migrate(app, db)

#jwt processes 
secret_key = base64.b64encode(os.urandom(24)).decode('utf-8')
print(secret_key)


# register route 
@app.route('/register', methods=['POST'])
def register():
    '''
    Register a new users:
    ---
    tags: 
       - Authentication
    parameters:
       - name: username
         in: body 
         type: string 
         required: true
         description: User's username
       - name: email
         in: body 
         type: string 
         required: true
         description: User's email
       - name: password
         in: body 
         type: string 
         required: true
         description: User's password
    responses:
       201:
         description: user was registered successfully 
         schema:
            type: object 
            properties:
               message:
                  type: string 
                  description: user was registered successfully
        400:
           description: Bad request, invalid input data 
    '''
    # get our json data 
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    # regex logic to check on password pattern 
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username,email=email,password=hashed_password)
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'user registered successfully'})


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    user = User.query.filter_by(email=email).first()
    
    if user and check_password_hash(user.password, password):
        # generate token with no expiry 
        # token = jwt.encode({'user_id': user.id},secret_key,algorithm='HS256')
        # print(token)
        
        # generate one with expiry date 
        expiration_time = datetime.utcnow() + timedelta(hours=1)
        token = jwt.encode({'user_id': user.id, 'exp': expiration_time},secret_key,algorithm='HS256')
        print(token)
        return jsonify({'message' : 'Login successful' , 'token': token})
    else:
        return jsonify({'message' : 'Invalid user credentials.'})

# protecting routes 
# helper function to decode jwt 
def decode_token(token):
    try:
        payload = jwt.decode(token,secret_key,algorithms='HS256')
        return payload
    except jwt.ExpiredSignatureError:
        return 'Token has expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token provided'


@app.route('/protected', methods=['GET'])
def proctected_route():
    # we check if request is made using an authorized token 
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message'  : 'Authorization crendentials missing'})
    
    token = token.split(' ')[1]
    # decode the token 
    payload = decode_token(token)
    if isinstance(payload, str):
        return jsonify({'message': payload}), 401
    
    user_id = payload.get('user_id')
    #I can perform further operations as intended for the route 
    return jsonify({'message' : f'Access granted to the user{user_id}'})


@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    
    if user:
        # generate a token for reset purposes
        token = ''.join(random.choices(string.ascii_letters + string.digits , k=20))
        expiration_time = datetime.utcnow() + timedelta(hours=1)
        reset_token = PasswordResetToken(user_id=user.id,token=token,expiration=expiration_time)
        # sent this token to the users email
        db.session.add(reset_token)
        db.session.commit()
        return jsonify({'message': 'Password reset token sent', 'token': token})
    
    return jsonify({'message': 'user not found'})


@app.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    data = request.get_json()
    new_pass = data.get('new_pass')
    
    reset_token = PasswordResetToken.query.filter_by(token=token).first()
    if reset_token and reset_token.expiration > datetime.utcnow():
        user = User.query.filter_by(id=reset_token.user_id).first()
        hashed_pass = generate_password_hash(new_pass,method='pbkdf2:sha256')
        user.password = hashed_pass
        
        # delete 
        db.session.delete(reset_token)
        db.session.commit()
        
        return jsonify({'message': 'password reset successfully'})
    
    return jsonify({'message' : 'token is invalid'})
              
        
        

if __name__ == '__main__':
    app.run(port=3000,debug=True)