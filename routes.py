from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from models import User, db
from forms import RegisterForm, LoginForm

def register_routes(app):
    @app.route('/')
    def home():
        return render_template('base.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            user = User.query.filter_by(username=username).first()

            # Debug: Print the username and password
            print(f"Login Attempt: Username={username}, Password={password}")

            # Check if the user exists
            if user:
                # Debug: Print the user details
                print(f"User Found: {user.username}, Approved: {user.is_approved}, Active: {user.is_active}")

                # Check if the password is correct
                if check_password_hash(user.password, password):
                    # Check if the user is approved
                    if user.is_approved:
                        # Check if the user is active
                        if user.is_active:
                            login_user(user)  # Log in the user
                            flash('Logged in successfully!', 'success')

                            # Debug: Print the current user
                            print(f"Logged in as: {current_user.username}")

                            # Redirect admin to the admin page
                            if user.username == 'admin':
                                return redirect(url_for('admin'))
                            else:
                                return redirect(url_for('dashboard'))
                        else:
                            # User is approved but deactivated
                            flash('Your account has been deactivated. Please contact the admin to reactivate your account.', 'warning')
                    else:
                        flash('Your account is pending admin approval. Please wait.', 'warning')
                else:
                    flash('Invalid username or password', 'danger')
            else:
                flash('Invalid username or password', 'danger')

        # Debug: Print form errors
        if form.errors:
            print("Form Errors:", form.errors)

        return render_template('login.html', form=form)

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        form = RegisterForm()
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            code = form.code.data  # Get the code from the form

            # Check if the username already exists
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Username already taken. Please choose a different username.', 'danger')
                return redirect(url_for('register'))

            # Hash the password and create a new user
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password, code=code, is_approved=False, is_active=True)
            db.session.add(new_user)
            db.session.commit()

            flash('Registration successful! Please wait for admin approval.', 'success')
            return redirect(url_for('login'))

        return render_template('register.html', form=form)

    @app.route('/admin', methods=['GET', 'POST'])
    @login_required
    def admin():
        # Ensure only the admin can access this page
        if current_user.username != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))

        # Create a dummy form for CSRF protection
        class DummyForm(FlaskForm):
            pass

        form = DummyForm()

        # Get all users
        all_users = User.query.all()

        if request.method == 'POST':
            user_id = request.form.get('user_id')
            action = request.form.get('action')  # 'approve', 'delete', 'deactivate', or 'activate'

            user = User.query.get(user_id)
            if user:
                if action == 'approve':
                    user.is_approved = True
                    db.session.commit()
                    flash(f'User {user.username} has been approved.', 'success')
                elif action == 'delete':
                    db.session.delete(user)
                    db.session.commit()
                    flash(f'User {user.username} has been deleted.', 'danger')
                elif action == 'deactivate':
                    user.is_active = False
                    db.session.commit()
                    flash(f'User {user.username} has been deactivated.', 'warning')
                elif action == 'activate':
                    user.is_active = True
                    db.session.commit()
                    flash(f'User {user.username} has been activated.', 'success')

            return redirect(url_for('admin'))

        return render_template('admin.html', all_users=all_users, form=form)

    @app.route('/dashboard')
    @login_required
    def dashboard():
        return render_template('dashboard.html', user=current_user)

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('You have been logged out.', 'info')
        return redirect(url_for('home'))