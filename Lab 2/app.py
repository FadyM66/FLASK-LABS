
from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from enum import Enum
import base64
import bcrypt
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = os.urandom(24)
db = SQLAlchemy(app)

# Models
class Role(Enum):
    user = 'user'
    admin = 'admin'
    
class User(db.Model):
    id = db.Column(db.Integer , primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(130), nullable=False)
    img = db.Column(db.LargeBinary, nullable=False, default='defaultprofileimg.png')
    role = db.Column(db.Enum(Role), nullable=False, default=Role.user)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    modified_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __str__(self):
        return self.username
    
    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.img}')"
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'password': self.password,  # Be cautious sharing passwords
            'role': self.role.value,
            'created_at': self.created_at.isoformat(),
            'modified_at': self.modified_at.isoformat(),
            'img': base64.b64encode(self.img).decode('utf-8') if self.img else None
        }

    
# class Book(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String, nullable=True)
#     price = db.Column(db.Integer, nullable=True, default='Not available')
#     createdat = db.Column(db.DateTime, default=datetime.utcnow)
#     modifiedat = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
#     def __str__(self):
#         return self.name
    
#     def __repr__(self):
#         return f"Book('{self.name}', '{self.price}')"

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    author = db.Column(db.String, nullable=False)
    price = db.Column(db.Float, nullable=True, default=0.0)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    modified_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    owner = db.relationship('User', back_populates='books')
    
    def __str__(self):
        return self.title
    
    def __repr__(self):
        return f"Book('{self.title}', '{self.author}', '{self.price}')"

# Update User model to include a relationship to Book
User.books = db.relationship('Book', back_populates='owner')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')

    elif request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        image = request.files['image']

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username is already taken. Please choose a different username.', 'danger')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('signup'))

        # Process the image
        img = image.read() if image else None
        passwd = hash_password(password)

        new_user = User(username=username, password=passwd, img=img)
        db.session.add(new_user)
        db.session.commit()

        flash('User registered successfully!', 'success')
        return redirect(url_for('signin'))






def hash_password(passwd):
    try:
        hashed_password = bcrypt.hashpw(passwd.encode('utf-8'), bcrypt.gensalt())
    except Exception as e:
        return f"error: {e}"
    else:
        return hashed_password
        

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'GET':
        return render_template('signin.html')

    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the user exists
        user = User.query.filter_by(username=username).first()
        if not user:
            flash('Username not found. Please check your username.', 'danger')
            return redirect(url_for('signin'))

        # Verify the password
        if not bcrypt.checkpw(password.encode('utf-8'), user.password):
            flash('Incorrect password. Please try again.', 'danger')
            return redirect(url_for('signin'))

        # Successful login, store user info in session
        session['user_id'] = user.id
        session['username'] = user.username
        flash('Logged in successfully!', 'success')
        return redirect(url_for('home'))

    

def check_tables():
    with app.app_context():
        inspector = db.inspect(db.engine)
        if not inspector.has_table('user'):
            db.create_all()
            print('Database has been created.')
        else:
            print('Database is already created.')

@app.route('/', methods=['GET'])
@app.route('/home', methods=['GET'])
def home():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('signin'))

    user_books = Book.query.filter_by(owner_id=session['user_id']).all()
    return render_template('home.html', books=user_books)



@app.route('/add_book', methods=['GET', 'POST'])
def add_book():
    if 'user_id' not in session:
        flash('Please log in to add a book.', 'danger')
        return redirect(url_for('signin'))

    if request.method == 'POST':
        title = request.form['title']
        author = request.form['author']
        price = request.form.get('price', 0.0, type=float)

        new_book = Book(title=title, author=author, price=price, owner_id=session['user_id'])
        db.session.add(new_book)
        db.session.commit()

        flash('Book added successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('add_book.html')



@app.route('/remove_book/<int:book_id>', methods=['POST'])
def remove_book(book_id):
    if 'user_id' not in session:
        flash('Please log in to remove a book.', 'danger')
        return redirect(url_for('signin'))

    book = Book.query.get(book_id)
    if book and book.owner_id == session['user_id']:
        db.session.delete(book)
        db.session.commit()
        flash('Book removed successfully!', 'success')
    else:
        flash('Book not found or you do not have permission to delete it.', 'danger')

    return redirect(url_for('home'))




@app.route('/admin_dashboard', methods=['GET'])
def admin_dashboard():
    if 'user_id' not in session or User.query.get(session['user_id']).role != Role.admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))

    users = User.query.all()
    books = Book.query.all()
    return render_template('admin_dashboard.html', users=users, books=books)





if __name__=='__main__':
    check_tables()
    app.run(debug=True, port=4080)


