# app.py

from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, login_required, current_user
)
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename, redirect
from wtforms import (
    StringField, PasswordField, SubmitField, TextAreaField, FileField
)
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
import os
from datetime import datetime

# Initialize the Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key'  # Replace with a strong secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'  # Use SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi'}

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect to 'login' view if not authenticated

# User loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    posts = db.relationship('Post', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

post_tags = db.Table('post_tags',
    db.Column('post_id', db.Integer, db.ForeignKey('posts.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tags.id'), primary_key=True)
)

class Tag(db.Model):
    __tablename__ = 'tags'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), unique=True, nullable=False)

    posts = db.relationship('Post', secondary=post_tags, back_populates='tags',lazy='dynamic')

class Post(db.Model):
    __tablename__ = 'posts'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    media_filename = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    tags = db.relationship('Tag', secondary=post_tags, back_populates='posts',lazy='dynamic')

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=64)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=64)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class PostForm(FlaskForm):
    content = TextAreaField('Content', validators=[DataRequired()])
    tags = StringField('Tags (comma-separated)', validators=[Length(max=100)])
    media = FileField('Media')
    submit = SubmitField('Post')

# Utility Functions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_media_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return filename
    return None

# Routes
@app.route('/')
@app.route('/index')
@login_required
def index():
    posts = Post.query.order_by(Post.timestamp.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password.')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    form = PostForm()
    if form.validate_on_submit():
        media_filename = None
        if form.media.data:
            media_filename = save_media_file(form.media.data)
            if not media_filename:
                flash('Invalid file type.')
                return redirect(request.url)

        post = Post(
            content=form.content.data,
            author=current_user,
            media_filename=media_filename
        )

        # Add the post to the session before associating tags
        db.session.add(post)

        # Handle tags
        tag_names = [name.strip() for name in form.tags.data.split(',') if name.strip()]
        for name in tag_names:
            tag = Tag.query.filter_by(name=name).first()
            if not tag:
                tag = Tag(name=name)
                db.session.add(tag)  # Add new tag to the session
            post.tags.append(tag)

        db.session.commit()
        flash('Post created successfully.')
        return redirect(url_for('index'))

    return render_template('create_post.html', form=form)

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)  # Forbidden

    form = PostForm(obj=post)
    if form.validate_on_submit():
        # Update post content
        post.content = form.content.data

        # Handle media file (optional)
        if form.media.data:
            media_filename = save_media_file(form.media.data)
            if not media_filename:
                flash('Invalid file type.')
                return redirect(request.url)
            post.media_filename = media_filename
        else:
            # If no new media is uploaded, keep the existing one
            pass

        # Update tags
        for tag in post.tags.all():
             post.tags.remove(tag)

        tag_names = [name.strip() for name in form.tags.data.split(',') if name.strip()]
        for name in tag_names:
            tag = Tag.query.filter_by(name=name).first()
            if not tag:
                tag = Tag(name=name)
                db.session.add(tag)
            post.tags.append(tag)

        db.session.commit()
        flash('Post updated successfully.')
        return redirect(url_for('index'))

    # Pre-fill form fields
    form.tags.data = ', '.join([tag.name for tag in post.tags])

    return render_template('edit_post.html', form=form, post=post)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)  # Forbidden

    db.session.delete(post)
    db.session.commit()
    flash('Post deleted successfully.')
    return redirect(url_for('index'))


@app.route('/search', methods=['GET'])
@login_required
def search():
    query = request.args.get('q', '')
    if query:
        posts = Post.query.filter(Post.content.ilike(f'%{query}%')).all()  # maybe also be able to search based om different things as well
    else:
        posts = []
    return render_template('search.html', posts=posts, query=query)

@app.route('/tag/<string:tag_name>')
@login_required
def tag_posts(tag_name):
    tag = Tag.query.filter_by(name=tag_name).first_or_404()
    posts = tag.posts.order_by(Post.timestamp.desc()).all()
    return render_template('tag_posts.html', posts=posts, tag_name=tag_name)


# Error Handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# Create the database tables if they don't exist
with app.app_context():
    db.create_all()

# Run the application
if __name__ == '__main__':
    app.run(debug=True)
