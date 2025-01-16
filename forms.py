from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=1, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=1)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    code = StringField('Code', validators=[DataRequired(), Length(min=1, max=20)])  # New field
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=1, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=1)])
    submit = SubmitField('Login')


    