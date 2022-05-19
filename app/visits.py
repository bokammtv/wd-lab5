from datetime import datetime
import math
import io
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file
from flask_login import login_required, current_user
from app import mysql
from auth import check_rights


bp = Blueprint('visits', __name__, url_prefix='/visits')

PER_PAGE = 15

def convert_to_csv(records):
    fields = records[0]._fields
    result = 'No,' + ','.join(fields) + '\n'
    for i, record in enumerate(records):
        result += f'{i+1},' + ','.join([str(getattr(record, f, '')) for f in fields]) + '\n'
    return result


def generate_report(records):
    buffer = io.BytesIO()
    buffer.write(convert_to_csv(records).encode('utf-8'))
    buffer.seek(0)
    return buffer
    


@bp.route('/logs/<int:user_id>')
@login_required
@check_rights('show')
def logs(user_id):
    page = request.args.get('page', 1, type=int)
    with mysql.connection.cursor(named_tuple=True) as cursor:
        cursor.execute('SELECT COUNT(*) AS count FROM visit_logs;')
        total_count = cursor.fetchone().count
    total_pages = math.ceil(total_count/PER_PAGE)
    with mysql.connection.cursor(named_tuple=True) as cursor:
        if current_user.is_admin:
            cursor.execute(('SELECT visit_logs.*, users_1.last_name, users_1.first_name, users_1.middle_name '
                        'FROM visit_logs LEFT JOIN users_1 ON visit_logs.user_id = users_1.id ORDER BY visit_logs.created_at DESC '
                        'LIMIT %s OFFSET %s;'), (PER_PAGE, PER_PAGE*(page-1)))
        else:
            cursor.execute(('SELECT visit_logs.*, users_1.last_name, users_1.first_name, users_1.middle_name '
                        'FROM visit_logs LEFT JOIN users_1 ON visit_logs.user_id = users_1.id WHERE user_id=%s ORDER BY visit_logs.created_at DESC '
                        'LIMIT %s OFFSET %s;'), (user_id, PER_PAGE, PER_PAGE*(page-1)))
        records = cursor.fetchall()
    return render_template('visits/logs.html', records=records, page=page, total_pages=total_pages)


@bp.route('/stats/users')
@login_required
@check_rights('super_user')
def users_stat():
    query = ('SELECT users_1.last_name, users_1.first_name, users_1.middle_name, COUNT(*) AS count '
             'FROM users_1 RIGHT JOIN visit_logs ON visit_logs.user_id = users_1.id '
             'GROUP BY visit_logs.user_id '
             'ORDER BY count DESC;')
    
    with mysql.connection.cursor(named_tuple=True) as cursor:
        cursor.execute(query)
        records = cursor.fetchall()

    if request.args.get('download_csv'):
        f = generate_report(records)
        filename = datetime.now().strftime('%d_%m_%Y_%H_%M_%S') + '_users_stat.csv'
        return send_file(f, mimetype='text/csv', as_attachment=True, attachment_filename=filename)
    
    return render_template('visits/users_stat.html', records=records)

@bp.route('/stats/pages')
@login_required
@check_rights('super_user')
def pages_stat():
    query = ('SELECT visit_logs.path, COUNT(*) AS count '
             'FROM visit_logs '
             'GROUP BY visit_logs.path '
             'ORDER BY count DESC;')
            

    with mysql.connection.cursor(named_tuple=True) as cursor:
        cursor.execute(query)
        records = cursor.fetchall()

    if request.args.get('download_csv'):
        f = generate_report(records)
        filename = datetime.now().strftime('%d_%m_%Y_%H_%M_%S') + '_pages_stat.csv'
        return send_file(f, mimetype='text/csv', as_attachment=True, attachment_filename=filename)

    return render_template('visits/pages_stat.html', records=records)
