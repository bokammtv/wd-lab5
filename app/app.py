from flask import Flask, render_template, session, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from mysql_db import MySQL
import mysql.connector as connector

app = Flask(__name__)
application = app


app.config.from_pyfile('config.py')

mysql = MySQL(app)

from auth import init_login_manager, bp as auth_bp, check_rights
from visits import bp as visits_bp


init_login_manager(app)
app.register_blueprint(auth_bp)
app.register_blueprint(visits_bp)

CREATE_PARAMS = ['login', 'password', 'first_name',
                 'last_name', 'middle_name', 'role_id']

UPDATE_PARAMS = ['first_name', 'last_name', 'middle_name', 'role_id']

UPDATE_PASS_PARAMS = ['current_password', 'new_password', 'new_password1', 'role_id']

CHECK_PARAMS = {'login': 'логин', 'password': 'пароль', 'first_name': 'имя',
                 'last_name': 'фамилия', 'current_password': 'текущий пароль',
                 'new_password': 'новый пароль', 'new_password1': 'подтверждение пароля'}

@app.before_request
def log_visit_info():
    if request.endpoint == 'static' or request.args.get('download_csv'):
        return None
    user_id = getattr(current_user, 'id', None)
    query = 'INSERT INTO visit_logs (user_id, path) VALUES (%s, %s);'
    with mysql.connection.cursor(named_tuple=True) as cursor:
            try:
                cursor.execute(query, (user_id, request.path))
                mysql.connection.commit()
            except:
                pass

##############
def check_login(login):
    if len(login) < 5:
        return False
    alphabet = ''
    for letter in range(48, 58):
        alphabet = alphabet + chr(letter)
    for letter in range(65, 91):
        alphabet = alphabet + chr(letter)
    for letter in range(97, 123):
        alphabet = alphabet + chr(letter)
    for one_char in login:
        if one_char not in alphabet:
            return False
    return True

def check_pass(password):
    if len(password) < 8:
        return False
    alphabet = ''
    u_flag = False
    l_flag = False
    n_flag = False
    for letter in range(33, 127):
        alphabet = alphabet + chr(letter)
    for one_char in password:
        for letter in range(0, 94):
            if one_char in alphabet[letter]:
                if letter>14 and letter<25:
                    n_flag = True
                if letter>31 and letter<58:
                    u_flag = True
                if letter>63 and letter<90:
                    l_flag = True
        if one_char not in alphabet:
            return False
    return n_flag and u_flag and l_flag
    
def is_equal():
    p1 = request.form.get('new_password')
    p2 = request.form.get('new_password1')
    if (p1 == p2):
        return True
    return False

def check_params(params_list):#реализовано
    invalid_params = {}
    for param_name in params_list:
        value = request.form.get(param_name)
        if (value == '') and (param_name in CHECK_PARAMS) :
            invalid_params[param_name] = request.form.get(param_name)
        if ((param_name == 'login') and (not check_login(value))):
            invalid_params[param_name] = value
        if (param_name in ['password', 'new_password']) and (not check_pass(value)):
            invalid_params[param_name] = value
        if (param_name == 'new_password1') and (not is_equal()):
            invalid_params[param_name] = value
    if invalid_params:
        flash('Проверьте правильность заполнения формы', 'info')
    return invalid_params
##############
def request_params(params_list):
    params = {}
    for param_name in params_list:
        params[param_name] = request.form.get(param_name) or None
    return params


def load_roles():
    with mysql.connection.cursor(named_tuple=True) as cursor:
        cursor.execute('SELECT id, name, description FROM roles;')
        roles = cursor.fetchall()
    return roles


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/users')
def users():
    with mysql.connection.cursor(named_tuple=True) as cursor:
        cursor.execute(
            'SELECT users_1.*, roles.description AS role_name FROM users_1 LEFT JOIN roles ON users_1.role_id = roles.id;')
        users = cursor.fetchall()
    return render_template('users/index.html', users=users)


@app.route('/users/new')
@login_required
@check_rights('create')
def new():
    return render_template('users/new.html', user={}, roles=load_roles(), invalid_params={})


@app.route('/users/create', methods=['POST'])
@login_required
@check_rights('create')
def create():
    invalid_params = check_params(CREATE_PARAMS)#добавлено
    params = request_params(CREATE_PARAMS)
    params['role_id'] = int(params['role_id']) if params['role_id'] else None
    if invalid_params:
        return render_template('users/new.html', user=params, roles=load_roles(), invalid_params=invalid_params)
    else:
        with mysql.connection.cursor(named_tuple=True) as cursor:
            try:
                cursor.execute(
                    ('INSERT INTO users_1 (login, password_hash, last_name, first_name, middle_name, role_id)'
                    'VALUES (%(login)s, SHA2(%(password)s, 256), %(last_name)s, %(first_name)s, %(middle_name)s, %(role_id)s);'),
                    params
                )
                mysql.connection.commit()
            except connector.Error:
                flash('Пользователь с таким логином уже существует. Ошибка сохранения', 'danger')
                return render_template('users/new.html', user=params, roles=load_roles(), invalid_params=invalid_params)
    flash(
        f"Пользователь {params.get('login')} был успешно создан! ", 'success')
    return redirect(url_for('users'))


@app.route('/users/<int:user_id>')
@login_required
@check_rights('show')
def show(user_id):
    with mysql.connection.cursor(named_tuple=True) as cursor:
        cursor.execute('SELECT * FROM users_1 WHERE id=%s;' % (user_id, ))
        user = cursor.fetchone()
    return render_template('users/show.html', user=user)


@app.route('/users/<int:user_id>/edit')
@login_required
@check_rights('update')
def edit(user_id):
    with mysql.connection.cursor(named_tuple=True) as cursor:
        cursor.execute('SELECT * FROM users_1 WHERE id=%s;' % (user_id, ))
        user = cursor.fetchone()
    return render_template('users/edit.html', user=user, roles=load_roles())


@app.route('/users/<int:user_id>/update', methods=['POST'])
@login_required
@check_rights('update')
def update(user_id):
    invalid_params = check_params(UPDATE_PARAMS)#добавлено
    params = request_params(UPDATE_PARAMS)
    params['role_id'] = int(params['role_id']) if params['role_id'] else None
    params['id'] = user_id
    if invalid_params:
        return render_template('users/edit.html', user=params, roles=load_roles(), invalid_params=invalid_params)
    else:
        if not current_user.can('assign_role'):
            del params['role_id']
        with mysql.connection.cursor(named_tuple=True) as cursor:
            try:
                cursor.execute((
                    f"UPDATE users_1 SET {', '.join(['{0}=%({0})s'.format(k) for k, _ in params.items() if k!='id'])} "
                    'WHERE id=%(id)s;'), params)
                mysql.connection.commit()
            except connector.Error:
                flash('Ошибка сохранения', 'danger')
                return render_template('users/edit.html', user=params, roles=load_roles(), invalid_params=invalid_params)
    flash("Пользователь был успешно обновлен! ", 'success')
    return redirect(url_for('show', user_id=user_id))


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@check_rights('delete')
def delete(user_id):
    with mysql.connection.cursor(named_tuple=True) as cursor:
        try:
            cursor.execute('DELETE FROM users_1 WHERE id=%s;', (user_id, ))
            mysql.connection.commit()
        except connector.Error:
            flash('Не удалось удалить пользователя', 'danger')
            return redirect(url_for('users'))
    flash("Пользователь был успешно удален! ", 'success')
    return redirect(url_for('users'))


@app.route('/users/<int:user_id>/edit_pass')
@login_required
@check_rights('update_pass')
def edit_pass(user_id):
    with mysql.connection.cursor(named_tuple=True) as cursor:
        cursor.execute('SELECT * FROM users_1 WHERE id=%s;' % (user_id, ))
        user = cursor.fetchone()
    return render_template('users/edit_pass.html', user=user, roles=load_roles(), invalid_params={})

@app.route('/users/<int:user_id>/update_pass', methods=['POST'])
@login_required
@check_rights('update_pass')
def update_pass(user_id):
    invalid_params = check_params(UPDATE_PASS_PARAMS)#добавлено
    params = request_params(UPDATE_PASS_PARAMS)
    params['role_id'] = int(params['role_id']) if params['role_id'] else None
    params['id'] = user_id
    if invalid_params:
        return render_template('users/edit_pass.html', user=params, roles=load_roles(), invalid_params=invalid_params)
    else:
        if not current_user.can('assign_role'):
            del params['role_id']
        with mysql.connection.cursor(named_tuple=True) as cursor:
            cursor.execute(("SELECT * FROM users_1 WHERE id=%(id)s AND password_hash=SHA2(%(current_password)s, 256);"), params)
            user = cursor.fetchone()
            if user is None:
                flash('Неверный пароль. Ошибка сохранения', 'danger')
                return render_template('users/edit_pass.html', user=params, roles=load_roles(), invalid_params=invalid_params)
            else:
                cursor.execute((
                    "UPDATE users_1 SET password_hash=SHA2(%(new_password1)s, 256) WHERE id=%(id)s AND password_hash=SHA2(%(current_password)s, 256);"), params)
                mysql.connection.commit()
    flash("Пароль был успешно обновлен! ", 'success')
    return redirect(url_for('show', user_id=user_id))