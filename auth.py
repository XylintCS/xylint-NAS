from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from wtforms.validators import InputRequired, Length, Regexp, EqualTo
from wtforms import StringField, PasswordField, SubmitField
from app.encryption import hash_password, verify_password
from sqlalchemy.exc import SQLAlchemyError
from app.models import User, File
from flask_wtf import FlaskForm
from app import db
import os

auth = Blueprint('auth', __name__)

class RegistrationForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[
            InputRequired(),
            Length(min=3, max=30),
            Regexp(r'^[a-zA-Z0-9_.-]+$', message="Username can contain letters, numbers, and ._- only")
        ],
        render_kw={"autocomplete": "off"}
    )
    password = PasswordField(
        'Password',
        validators=[
            InputRequired(),
            Length(min=8),
            EqualTo('confirm', message='Passwords must match')
        ],
        render_kw={"autocomplete": "new-password"}
    )
    confirm = PasswordField(
        'Confirm Password',
        render_kw={"autocomplete": "new-password"}
    )
    submit = SubmitField('Register')

from sqlalchemy.exc import SQLAlchemyError

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('auth/register.html', form=form)

        user = User(username=username, password_hash=hash_password(password))
        try:
            db.session.add(user)
            db.session.commit()
            login_user(user, remember=False)
            flash('Registration successful!', 'success')
            return redirect(url_for('main.dashboard'))
        except SQLAlchemyError as e:
            flash('Database error. Please try again later', 'error')

    else:
        if form.errors:
            print("Form validation errors:", form.errors)

    return render_template('auth/register.html', form=form)



class LoginForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[InputRequired(), Length(min=3, max=30)],
        render_kw={"autocomplete": "off"}
    )
    password = PasswordField(
        'Password',
        validators=[InputRequired()],
        render_kw={"autocomplete": "current-password"}
    )
    submit = SubmitField('Login')

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first()
        if user and verify_password(user.password_hash, form.password.data):
            login_user(user, remember=False)
            flash('Logged in successfully', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('auth.login'))


@auth.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    password = request.form.get('password', '')

    if not verify_password(current_user.password_hash, password):
        flash('Invalid password', 'error')
        return redirect(url_for('main.settings'))

    user = User.query.get(current_user.id)
    if not user:
        flash('Account not found', 'error')
        return redirect(url_for('main.settings'))

    save_dir = None
    if current_user.selected_drive and os.path.ismount(current_user.selected_drive):
        save_dir = os.path.join(current_user.selected_drive, 'NAS_Data')

    try:
        for f in File.query.filter_by(user_id=user.id).all():
            if save_dir:
                file_path = os.path.join(save_dir, f.filename_enc)
                if os.path.isfile(file_path):
                    os.remove(file_path)
            db.session.delete(f)
        with db.session.begin():
            db.session.delete(user)
    except Exception as e:
        flash('Error deleting account files. Please try again.', 'error')
        return redirect(url_for('main.settings'))

    logout_user()
    flash('Your account and all stored files have been deleted successfully', 'success')
    return redirect(url_for('main.index'))