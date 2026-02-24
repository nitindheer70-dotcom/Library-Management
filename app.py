from flask import Flask, flash, redirect, render_template, request, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask.views import MethodView
from flask.blueprints import Blueprint
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps
import os
import pandas as pd  # Added for bulk import

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'xlsx', 'xls'}

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
migrate = Migrate(app, db)

# Configure login manager
login_manager.login_view = 'main.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

main = Blueprint("main", __name__)

# ========================
# MODELS
# ========================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    admin = db.Column(db.Boolean, default=False)
    
    # Relationship
    issued_copies = db.relationship("Copy", backref="user", lazy=True)


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True)
    author = db.Column(db.String(255))
    description = db.Column(db.Text)
    cover_image = db.Column(db.String(255), nullable=True)
    date_added = db.Column(db.DateTime, default=datetime.now)

    total_copy = db.Column(db.Integer, default=0)
    issued_copy = db.Column(db.Integer, default=0)
    present_copy = db.Column(db.Integer, default=0)

    copies = db.relationship("Copy", backref="book", cascade="all, delete-orphan")


class Copy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    issued_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    date_added = db.Column(db.DateTime, default=datetime.now)
    date_issued = db.Column(db.DateTime, nullable=True)
    date_return = db.Column(db.DateTime, nullable=True)


# ========================
# AUTH
# ========================

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def requires_admin(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Please log in first!", "warning")
            return redirect(url_for("main.login"))
        if not current_user.admin:
            flash("Admin access required!", "danger")
            return redirect(url_for("main.index"))
        return f(*args, **kwargs)
    return wrapped


# ========================
# ROUTES
# ========================

@main.route("/")
def index():
    books = Book.query.all()
    return render_template("index.html", books=books, year=datetime.now().year)


@main.route("/dashboard")
@login_required
def dashboard():
    copies = Copy.query.filter_by(issued_by=current_user.id).all()
    return render_template("dashboard.html", books=copies, year=datetime.now().year)


@main.route("/admin/dashboard")
@login_required
@requires_admin
def admin_dashboard():
    total_books = Book.query.count()
    total_users = User.query.count()
    total_copies = Copy.query.count()
    issued_books = Copy.query.filter(Copy.issued_by.isnot(None)).count()
    available_books = Copy.query.filter_by(issued_by=None).count()
    overdue_books = Copy.query.filter(
        Copy.date_return < datetime.now(),
        Copy.issued_by.isnot(None)
    ).count()

    books = Book.query.all()
    users = User.query.all()

    return render_template(
        "admin_dashboard.html",
        books=books,
        users=users,
        total_books=total_books,
        total_users=total_users,
        total_copies=total_copies,
        issued_books=issued_books,
        available_books=available_books,
        overdue_books=overdue_books,
        year=datetime.now().year
    )


# ========================
# ISSUE BOOK
# ========================

class IssueBookView(MethodView):
    decorators = [login_required]

    def get(self):
        books = Book.query.filter(Book.present_copy > 0).all()
        return render_template("issue.html", books=books)

    def post(self):
        book_id = int(request.form.get("book"))

        copy = Copy.query.filter_by(
            book_id=book_id,
            issued_by=None
        ).first()

        if copy:
            copy.issued_by = current_user.id
            copy.date_issued = datetime.now()
            copy.date_return = datetime.now() + timedelta(days=7)

            book = Book.query.get(book_id)
            book.issued_copy += 1
            book.present_copy -= 1

            db.session.commit()
            flash("Book issued successfully!", "success")
        else:
            flash("No copies available!", "danger")

        return redirect(url_for("main.dashboard"))


# ========================
# RETURN BOOK
# ========================

class ReturnBookView(MethodView):
    decorators = [login_required]

    def get(self):
        copies = Copy.query.filter_by(issued_by=current_user.id).all()
        return render_template("return.html", books=copies)

    def post(self):
        book_id = int(request.form.get("book"))

        copy = Copy.query.filter_by(
            book_id=book_id,
            issued_by=current_user.id
        ).first()

        if copy:
            copy.issued_by = None
            copy.date_issued = None
            copy.date_return = None

            book = Book.query.get(book_id)
            book.issued_copy -= 1
            book.present_copy += 1

            db.session.commit()
            flash("Book returned successfully!", "success")
        else:
            flash("Invalid return request!", "danger")

        return redirect(url_for("main.dashboard"))


# ========================
# ADD BOOK
# ========================

class AddBookView(MethodView):
    decorators = [login_required, requires_admin]

    def get(self):
        return render_template("add_book.html")

    def post(self):
        name = request.form.get("name")
        author = request.form.get("author")
        description = request.form.get("description")
        number = int(request.form.get("number"))

        if Book.query.filter_by(name=name).first():
            flash("Book already exists!", "danger")
            return redirect(url_for("main.add_book"))

        image = request.files.get("image")
        filename = None

        if image and image.filename != "":
            if '.' in image.filename and image.filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg'}:
                filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            else:
                flash("Invalid image format. Please upload PNG, JPG, or JPEG.", "danger")
                return redirect(url_for("main.add_book"))

        book = Book(
            name=name,
            author=author,
            description=description,
            total_copy=number,
            present_copy=number,
            issued_copy=0,
            cover_image=filename
        )

        db.session.add(book)
        db.session.commit()

        for _ in range(number):
            copy = Copy(book_id=book.id)
            db.session.add(copy)

        db.session.commit()

        flash("Book added successfully!", "success")
        return redirect(url_for("main.admin_dashboard"))


# ========================
# BULK IMPORT BOOKS FROM EXCEL
# ========================

@main.route("/admin/bulk-import", methods=["GET", "POST"])
@login_required
@requires_admin
def bulk_import():
    if request.method == "POST":
        # Check if file was uploaded
        if 'file' not in request.files:
            flash("No file selected!", "danger")
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash("No file selected!", "danger")
            return redirect(request.url)
        
        # Check file extension
        if file and (file.filename.endswith('.xlsx') or file.filename.endswith('.xls') or file.filename.endswith('.csv')):
            try:
                # Read the file based on extension
                if file.filename.endswith('.csv'):
                    df = pd.read_csv(file)
                else:
                    df = pd.read_excel(file)
                
                # DEBUG: Show actual column names
                actual_columns = list(df.columns)
                flash(f"Columns found: {actual_columns}", "info")
                
                # Create a clean mapping dictionary
                # We'll map based on exact names (including spaces)
                rename_dict = {}
                for col in df.columns:
                    col_stripped = col.strip()
                    if col_stripped == "Book Name":
                        rename_dict[col] = "name"
                    elif col_stripped == "Author":
                        rename_dict[col] = "author"
                    elif col_stripped == "Total Copies":
                        rename_dict[col] = "copies"
                    elif col_stripped == "Category":
                        rename_dict[col] = "description"
                    # You can add more mappings if needed
                
                # Apply renaming
                df.rename(columns=rename_dict, inplace=True)
                
                # Now check for required columns
                required_columns = ['name', 'author', 'copies']
                missing_columns = [col for col in required_columns if col not in df.columns]
                
                if missing_columns:
                    flash(f"Missing required columns after mapping: {missing_columns}", "danger")
                    flash(f"Available columns now: {list(df.columns)}", "info")
                    return redirect(request.url)
                
                # Track success and failures
                success_count = 0
                error_count = 0
                error_messages = []
                
                # Process each row
                for index, row in df.iterrows():
                    try:
                        # Check if book already exists
                        existing_book = Book.query.filter_by(name=row['name']).first()
                        if existing_book:
                            error_messages.append(f"Row {index + 2}: Book '{row['name']}' already exists")
                            error_count += 1
                            continue
                        
                        # Get description (if column exists)
                        description = row.get('description', '')
                        if pd.isna(description):
                            description = ''
                        
                        # Get number of copies
                        copies = int(row['copies'])
                        if copies <= 0:
                            error_messages.append(f"Row {index + 2}: Copies must be greater than 0")
                            error_count += 1
                            continue
                        
                        # Create book
                        book = Book(
                            name=row['name'],
                            author=row['author'],
                            description=description,
                            total_copy=copies,
                            present_copy=copies,
                            issued_copy=0,
                            cover_image=None  # No cover image for bulk import
                        )
                        
                        db.session.add(book)
                        db.session.flush()  # Get book ID
                        
                        # Create copies
                        for _ in range(copies):
                            copy = Copy(book_id=book.id)
                            db.session.add(copy)
                        
                        success_count += 1
                        
                    except Exception as e:
                        error_messages.append(f"Row {index + 2}: {str(e)}")
                        error_count += 1
                        continue
                
                # Commit all changes
                db.session.commit()
                
                # Flash summary message
                if success_count > 0:
                    flash(f"Successfully imported {success_count} books!", "success")
                if error_count > 0:
                    for error in error_messages[:5]:  # Show first 5 errors
                        flash(error, "danger")
                    if len(error_messages) > 5:
                        flash(f"... and {len(error_messages) - 5} more errors", "warning")
                
            except Exception as e:
                flash(f"Error reading file: {str(e)}", "danger")
                db.session.rollback()
        else:
            flash("Please upload a valid Excel (.xlsx, .xls) or CSV file", "danger")
        
        return redirect(url_for("main.admin_dashboard"))
    
    return render_template("bulk_import.html")

# ========================
# REDIRECT FOR OLD UPLOAD BOOKS ENDPOINT (FIXES BuildError)
# ========================

@main.route("/admin/upload-books", methods=["GET", "POST"])
@login_required
@requires_admin
def upload_books():
    """Redirect to bulk_import for backward compatibility."""
    return redirect(url_for('main.bulk_import'))


# ========================
# REMOVE BOOK
# ========================

@main.route("/remove/book/<int:book_id>")
@login_required
@requires_admin
def remove_book(book_id):
    book = Book.query.get_or_404(book_id)
    
    # Delete cover image if exists
    if book.cover_image:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], book.cover_image)
        if os.path.exists(image_path):
            os.remove(image_path)
    
    db.session.delete(book)
    db.session.commit()
    
    flash(f"Book '{book.name}' removed successfully!", "success")
    return redirect(url_for("main.admin_dashboard"))


# ========================
# VIEW BOOK DETAILS
# ========================

@main.route("/book/<int:book_id>")
def view_book(book_id):
    book = Book.query.get_or_404(book_id)
    return render_template("view_book.html", book=book, year=datetime.now().year)


# ========================
# ADMIN USER MANAGEMENT
# ========================

@main.route("/admin/users")
@login_required
@requires_admin
def admin_users():
    users = User.query.all()
    return render_template("admin_users.html", users=users, year=datetime.now().year)


@main.route("/admin/books")
@login_required
@requires_admin
def admin_books():
    books = Book.query.all()
    return render_template("admin_books.html", books=books, year=datetime.now().year)


# ========================
# REGISTER / LOGIN / LOGOUT
# ========================

@main.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        if current_user.admin:
            return redirect(url_for("main.admin_dashboard"))
        return redirect(url_for("main.dashboard"))
        
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if not name or not email or not password:
            flash("All fields are required!", "danger")
            return redirect(url_for("main.register"))
        
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("main.register"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered!", "danger")
            return redirect(url_for("main.register"))

        # Check if this is the first user - make them admin
        is_first_user = User.query.count() == 0
        
        hashed_password = generate_password_hash(password)
        user = User(
            name=name, 
            email=email, 
            password=hashed_password,
            admin=is_first_user
        )
        
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        flash("Registration successful!", "success")
        
        if user.admin:
            return redirect(url_for("main.admin_dashboard"))
        return redirect(url_for("main.dashboard"))

    return render_template("register.html")


@main.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.admin:
            return redirect(url_for("main.admin_dashboard"))
        return redirect(url_for("main.dashboard"))
        
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            
            if user.admin:
                flash(f"Welcome Admin {user.name}!", "success")
                return redirect(url_for("main.admin_dashboard"))
            else:
                flash(f"Welcome {user.name}!", "success")
                return redirect(url_for("main.dashboard"))
        else:
            flash("Invalid email or password!", "danger")

    return render_template("login.html")


@main.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("main.index"))


# ========================
# ADMIN ROUTES (Non-blueprint)
# ========================

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated and current_user.admin:
        return redirect(url_for('main.admin_dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password) and user.admin:
            login_user(user)
            flash('Admin login successful!', 'success')
            return redirect(url_for('main.admin_dashboard'))
        else:
            flash('Invalid admin credentials!', 'danger')
            return redirect(url_for('admin_login'))
    
    return render_template('admin.html')


# ========================
# ERROR HANDLERS
# ========================

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500


# ========================
# INIT
# ========================

# Register URL rules for MethodViews
main.add_url_rule("/issue/book", view_func=IssueBookView.as_view("issue_book"))
main.add_url_rule("/return/book", view_func=ReturnBookView.as_view("return_book"))
main.add_url_rule("/add/book", view_func=AddBookView.as_view("add_book"))

# Register blueprint
app.register_blueprint(main)

# Create database tables
with app.app_context():
    db.create_all()
    
    # Create admin user if no users exist
    if User.query.count() == 0:
        admin = User(
            name="Admin",
            email="admin@library.com",
            password=generate_password_hash("admin123"),
            admin=True
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin user created: admin@library.com / admin123")

if __name__ == '__main__':
    app.run(debug=True)