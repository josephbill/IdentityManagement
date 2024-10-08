from .dbconfig import db 

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(255), nullable=False)
    expiration = db.Column(db.DateTime, nullable=False)
    
    user = db.relationship('User', backref='password_reset_token')
    
    
    # OOP 