from flask import Flask, request, jsonify, render_template, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from collections.abc import Sequence


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///news.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'  # Replace with a strong secret key for session management

db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Search history model
class SearchHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    topic = db.Column(db.String(150), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

# Define a model for storing news articles
class NewsArticle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    url = db.Column(db.String(300), nullable=False)

    def __repr__(self):
        return f'<NewsArticle {self.title}>'

NEWS_API_KEY = 'pub_ae5f9f987bec4fb2b62cfc0aa0d67047'  # Replace with your Newsdata.io API key
NEWS_API_URL = 'https://newsdata.io/api/1/news'

@app.route('/')
@login_required
def home():
    return render_template('index.html')

@app.route('/search', methods=['POST'])
def search_news():
    topic = request.json.get('topic')
    if not topic:
        return jsonify({'error': 'Topic is required'}), 400

    # Fetch news articles from Newsdata.io API
    params = {
        'q': topic,
        'apikey': NEWS_API_KEY,
        'language': 'en'
    }
    response = requests.get(NEWS_API_URL, params=params)

    if response.status_code != 200:
        return jsonify({'error': 'Failed to fetch news articles'}), 500

    articles = response.json().get('results', [])
    return jsonify({'articles': articles})

@app.route('/ui')
@login_required
def ui():
    return render_template('index.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username already exists')
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return render_template('login.html', success='Registration successful! Please log in.')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect('/')  # Redirect to home page after login
        return render_template('login.html', error='Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return 'Logged out successfully'

@app.route('/summarize', methods=['POST'])
def summarize_article():
    content = request.json.get('content')
    if not content:
        return jsonify({'error': 'Content is required'}), 400

    # Sumy functionality removed; return placeholder error
    return jsonify({'error': 'Summarization feature is currently unavailable.'}), 501

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        user = User.query.filter_by(username=username).first()
        if not user:
            return render_template('reset_password.html', error='User not found')
        user.set_password(new_password)
        db.session.commit()
        return render_template('login.html', success='Password reset successful! Please log in.')
    return render_template('reset_password.html')

if __name__ == '__main__':
    app.run(debug=True)
