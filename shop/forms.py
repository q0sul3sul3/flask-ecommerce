from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField, FileRequired
from wtforms import IntegerField, PasswordField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from wtforms_sqlalchemy.fields import QuerySelectField

from .models import Category, Item, User


class RegisterForm(FlaskForm):
    username = StringField(
        'Username', validators=[DataRequired(), Length(min=4, max=20)]
    )
    email = StringField(
        'Email', validators=[Email(), DataRequired(), Length(min=4, max=50)]
    )
    password = PasswordField(
        'Password', validators=[DataRequired(), Length(min=4, max=20)]
    )
    comfirm_password = PasswordField(
        'Comfirm Password', validators=[EqualTo('password'), DataRequired()]
    )
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError(
                'Username already exists! Please try another Username.'
            )

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already exists! Please try another Email.')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')


class SearchForm(FlaskForm):
    search = StringField('Search', validators=[DataRequired(), Length(min=3)])
    submit = SubmitField('Search')


class AddItemForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=20)])
    category = QuerySelectField(
        query_factory=lambda: Category.query.all(), allow_blank=False, get_label='name'
    )
    description = TextAreaField('Description', validators=[DataRequired()])
    price = IntegerField('Price', validators=[DataRequired()])
    image = FileField(
        'Image',
        validators=[
            FileRequired(),
            FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!'),
        ],
    )
    submit = SubmitField('Submit')

    def validate_name(form, field):
        item = Item.query.filter_by(name=field.data).first()
        if item:
            raise ValidationError(f'{field.data} already exists!')

    def validate_price(form, field):
        if field.data < 1:
            raise ValidationError('Price must be greater than zero.')
