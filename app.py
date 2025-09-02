from flask import Flask
from flask_login import LoginManager, UserMixin
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
import os
from werkzeug.utils import secure_filename
import pandas as pd

app = Flask(__name__)


app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'xlsx', 'xls'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
migrate = Migrate(app, db)

from datetime import datetime, timedelta
from functools import wraps

from flask import flash, redirect, render_template, request, url_for
from flask.blueprints import Blueprint
from flask.views import MethodView
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

main = Blueprint("main", __name__)



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    book = db.relationship("Copy", backref="issue", lazy=True)
    admin = db.Column(db.Boolean, default=False)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True)
    author = db.Column(db.String(255))
    description = db.Column(db.Text)
    copy = db.relationship("Copy", backref=db.backref("posts", lazy=True), cascade="all,delete")
    total_copy = db.Column(db.Integer)
    issued_copy = db.Column(db.Integer)
    present_copy = db.Column(db.Integer)

class Copy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    issued_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    issued_copy = db.Column(db.Integer, default=0)
    present_copy = db.Column(db.Integer, default=1)
    date_issued = db.Column(db.DateTime, nullable=True)
    date_return = db.Column(db.DateTime, nullable=True)



def requires_admin(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if current_user.admin:
            return f(*args, **kwargs)
        return unauthorized()
    return wrapped

@login_manager.user_loader
def load_user(user_id: int):
    return User.query.get(user_id)

@main.route("/", methods=["GET"])
def index():
    """Home Page"""
    books = Book.query.all()
    if books:
        return render_template("index.html", year=datetime.now().year, books=books)
    flash("No books are in library!")
    return render_template("index.html", year=datetime.now().year)

class LoginView(MethodView):
    def get(self):
        return render_template("login.html", year=datetime.now().year)

    def post(self):
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if request.args.get("next"):
                return redirect(request.args.get("next"))
            return redirect(url_for("main.dashboard"))
        flash("Invalid Credentials!")
        return redirect(url_for("main.login"))

class RegisterView(MethodView):
    def get(self):
        return render_template("register.html", year=datetime.now().year)

    def post(self):
        name = request.form.get("name")
        email = request.form.get("email")
        password = generate_password_hash(request.form.get("password"), method="pbkdf2:sha256")
        if User.query.filter_by(email=email).first():
            flash("User already exists!")
            return redirect(url_for("main.register"))
        user = User(name=name, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        if request.args.get("next"):
            return redirect(request.args.get("next"))
        return redirect(url_for("main.dashboard"))

class AdminView(MethodView):
    def get(self):
        return render_template("admin.html", year=datetime.now().year)

    def post(self):
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email, admin=True).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if request.args.get("next"):
                return redirect(request.args.get("next"))
            return redirect(url_for("main.admin_dashboard"))
        flash("Invalid Credentials!")   
        return redirect(url_for("main.admin"))

@main.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    copies = Copy.query.filter_by(issued_by=current_user.id).all()
    if copies:
        return render_template("dashboard.html", year=datetime.now().year, books=copies)
    flash("You don't have books issued!")
    return render_template("dashboard.html", year=datetime.now().year)

@main.route("/admin/dashboard", methods=["GET"])
@login_required
@requires_admin
def admin_dashboard():
    books = Book.query.all()
    if books:
        return render_template(
            "admin_dashboard.html", books=books, year=datetime.now().year
        )
    flash("No books are there in library!")
    return render_template("admin_dashboard.html", year=datetime.now().year)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'xlsx', 'xls'}

@main.route('/upload_books', methods=['POST'])
@login_required
@requires_admin
def upload_books():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        process_excel_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        flash('Books uploaded successfully!')
        return redirect(url_for('main.admin_dashboard'))
    else:
        flash('Invalid file type. Please upload an Excel file.')
        return redirect(request.url)

def process_excel_file(filepath):
    df = pd.read_excel(filepath)
    for index, row in df.iterrows():
        book = Book.query.filter_by(name=row['Name']).first()
        if book:
            book.total_copy += row['Copies']
            book.present_copy += row['Copies']
        else:
            book = Book(
                name=row['Name'],
                author=row['Author'],
                description=row['Description'],
                total_copy=row['Copies'],
                present_copy=row['Copies'],
                issued_copy=0
            )
            db.session.add(book)
            db.session.commit()
        for _ in range(row['Copies']):
            copy = Copy(date_added=datetime.now(), book_id=book.id)
            book.copy.append(copy)
            db.session.add(copy)
        db.session.commit()


class AddBookView(MethodView):
    def get(self):
        return render_template("add_book.html", year=datetime.now().year)

    def post(self):
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                process_excel_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                flash('Books added from Excel file successfully!')
                return redirect(url_for('main.admin_dashboard'))
        else:
            name = request.form.get("name")
            author = request.form.get("author")
            description = request.form.get("description")
            number = int(request.form.get("number"))
            book = Book.query.filter_by(name=name).first()
            if book:
                flash("Book already exists!")
                return redirect(url_for("main.add_book"))
            book = Book(
                name=name,
                author=author,
                description=description,
                total_copy=number,
                present_copy=number,
                issued_copy=0,
            )
            for _ in range(number):
                copy = Copy(date_added=datetime.now())
                book.copy.append(copy)
            db.session.add(book)
            db.session.commit()
            flash("Book added successfully!")
            return redirect(url_for("main.admin_dashboard"))


@main.route("/admin/logout")
@login_required
@requires_admin
def admin_logout():
    return redirect(url_for("main.index"))

class IssueBookView(MethodView):
    def get(self):
        books = Book.query.filter(Book.present_copy > 0).all()
        if books:           
         return render_template("issue.html", books=Book.query.all(), year=datetime.now().year)
        else:
         flash("No books are currently available!")
         return render_template("issue.html", year=datetime.now().year, books=Book.query.all())

    def post(self):
     book_id = int(request.form.get("book"))
     book = Copy.query.filter_by(book=book_id, issued_by=None).first()

     if book:
        book.issued_by = current_user.id
        book.issued_copy += 1  # Assuming issued_copy is an attribute of Copy
        book.present_copy -= 1  # Assuming present_copy is an attribute of Copy
        book.date_issued = datetime.now()
        book.date_return = datetime.now() + timedelta(days=1)
        db.session.commit()
        flash("Book issued successfully!")
     else:
        flash("Book not available for issue!")

     return redirect(url_for("main.dashboard"))

class ReturnBookView(MethodView):
    def get(self):
        copies = Copy.query.filter_by(issued_by=current_user.id).all()
        if copies:
            return render_template(
                "return.html", books=copies, year=datetime.now().year
            )

        flash("You don't have any books issued!")
        return render_template(
            "return.html", year=datetime.now().year, books=Book.query.all()
        )

    def post(self):
        book_id = request.form.get("book")
        book = Copy.query.filter_by(
            book=int(book_id), issued_by=current_user.id
        ).first()
        book.issued_by = None
        book.date_issued = None
        book.date_return = None
        book.copies.issued_copy -= 1
        book.copies.present_copy += 1
        db.session.commit()
        flash("Book returned successfully!")
        return redirect(url_for("main.dashboard"))

class RemoveBookView(MethodView):
    def get(self):
        books = Book.query.filter_by(issued_copy=0).all()
        if books:
            return render_template(
                "remove_book.html", year=datetime.now().year, books=Book.query.all()
            )

        flash("No books are available to be removed!")
        return render_template(
            "remove_book.html", year=datetime.now().year, books=Book.query.all()
        )

    def post(self):
        book_id = int(request.form.get("book"))
        book = Book.query.filter_by(id=book_id).first()
        db.session.delete(book)
        db.session.commit()
        flash("Book removed successfully!")
        return redirect(url_for("main.admin_dashboard"))

main.add_url_rule("/register", view_func=RegisterView.as_view("register"))
main.add_url_rule("/login", view_func=LoginView.as_view("login"))
main.add_url_rule("/admin", view_func=AdminView.as_view("admin"))
main.add_url_rule(
    "/add/book",
    view_func=login_required(requires_admin(AddBookView.as_view("add_book"))),
)
main.add_url_rule(
    "/return/book", view_func=login_required(ReturnBookView.as_view("return_book"))
)
main.add_url_rule(
    "/remove/book", view_func=login_required(RemoveBookView.as_view("remove_book"))
)
main.add_url_rule(
    "/issue/book", view_func=login_required(IssueBookView.as_view("issue_book"))
)

@main.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.index"))

@login_manager.unauthorized_handler
def unauthorized():
    flash("You are not authorized to access the content!")
    return redirect(url_for("main.login"))

app.register_blueprint(main)
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)