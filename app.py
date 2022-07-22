from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from werkzeug.security import check_password_hash, generate_password_hash
import ansible_runner

app = Flask(__name__)
app.secret_key = 'bdbabdbatestsecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
manager = LoginManager(app)

ansible_path = '/Users/Denis_Babiichuk/PycharmProjects/BDBA-control/ansible'

class User (db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)


@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
@login_required
def index():
    # user_name = flask_login.current_user
    return render_template('index.html')


@app.route('/control', methods=['GET', 'POST'])
@login_required
def control():
    # play_name = request.form.get('playbook')
    # host_name = request.form.get('hostname')
    if request.method == "POST":
        r = ansible_runner.run(private_data_dir=ansible_path,
                               playbook='ping.yml')
        print("{}: {}".format(r.status, r.rc))
        # successful: 0
        for each_host_event in r.events:
            print(each_host_event['event'])
        print("Final status:")
        print(r.stats)
        status = r.status
        return render_template('control.html', status=status)
    return render_template('control.html')


@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    login = request.form.get('login')
    password = request.form.get('password')

    if login and password:
        user = User.query.filter_by(login=login).first()

        if user and check_password_hash(user.password, password):
            login_user(user)

            next_page = request.args.get('next')

            return redirect(next_page)
        else:
            flash('Login or password is not correct')
    else:
        flash('Please fill login and password fields')

    return render_template('login.html')


@app.route('/register-new-user', methods=['GET', 'POST'])
def register():
    login = request.form.get('login')
    password = request.form.get('password')
    password2 = request.form.get('password2')

    if request.method == 'POST':
        if not (login or password or password2):
            flash('Please, fill all fields!')
        elif password != password2:
            flash('Passwords are not equal!')
        else:
            hash_pwd = generate_password_hash(password)
            new_user = User(login=login, password=hash_pwd)
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('login_page'))

    return render_template('register.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login_page') + '?next=' + request.url)

    return response


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
