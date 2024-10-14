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
# generation token / reset password 
import random 
import string
import base64
# protection of routes using JWT : pip install jwt 
import jwt
import os 
# file uploads pip install cloudinary
import cloudinary
import cloudinary.uploader
from flask_swagger_ui import get_swaggerui_blueprint
from utils.cloudinaryconfig import cloudconfig
from flask_cors import CORS


app = Flask(__name__)
app.config['SWAGGER'] = {
    'title': 'Auth and Cloudinary APIs',
    'uiversion': 3
}

CORS(app=app)

swagger = Swagger(app)

# Database configuration and initialization
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://authenticationdb_user:vkFVCnZvmFHP3UjIuMflhO9p0ikfIpRM@dpg-cs6cefd6l47c73fc5ho0-a.oregon-postgres.render.com/authenticationdb'
db.init_app(app)
migrate = Migrate(app, db)

# Secret key for JWT
secret_key = base64.b64encode(os.urandom(24)).decode('utf-8')
print(secret_key)


# register route 
@app.route('/register', methods=['POST'])
def register():
    """
    Register a new user
    ---
    tags:
      - Authentication
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        schema:
          type: object
          required:
            - username
            - email
            - password
          properties:
            username:
              type: string
              description: User's username
            email:
              type: string
              description: User's email
            password:
              type: string
              description: User's password
    responses:
      201:
        description: User was registered successfully
      400:
        description: Invalid input data
    """

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
              
@app.route('/upload-profile-picture/<int:user_id>', methods=['POST'])
def upload_profile_picture(user_id):
    # json , email username password profile picture , get_data (formdata)
    # check if a file is submitted as part of the request 
    if 'file' not in request.files:
        return jsonify({'message' : 'file is not part of the request'}) , 400
    
    file = request.files['file']
    
    # check if file gets uploaded 
    if file.filename == '':
        return jsonify({'message': 'no selected file found'}), 400
    
    # upload process => cloudinary 
    try:
        # resource_type = 'auto' :( image,video,raw) : image : video : raw        
        result = cloudinary.uploader.upload(file, resource_type = "image")
        print(result)
        # secure_url 
        '''
        {
            'secure_url' : 'jkhfkdhfkdhfkdf.jvkdjfkdj'
        }
        '''
        image_url = result['secure_url']
        
        # retrieve the user 
        user = User.query.get(user_id)
        # update on profile pic 
        user.profile_pic = image_url
        db.session.commit()
        return jsonify({'message': 'image updated successfully', "url" : image_url})
        
    except Exception as e:
        return jsonify({'message': f'the error is {str(e)}'}), 500
        
        

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0",port=port,debug=True)