from functools import wraps
from flask import redirect, url_for, session,render_template,flash,request
from flask_login import current_user, UserMixin
from db import mysql, app
import MySQLdb


def role_required(required_role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if 'user_id' not in session:
                flash("Please log in to access this page.")
                return redirect(url_for("login"))
            if session.get('role_name').lower() != required_role.lower():
                flash("You do not have the required permissions.")
                return redirect(url_for("home"))
            return func(*args, **kwargs)
        return wrapper
    return decorator

class User(UserMixin):
    def __init__(self, id, username, role_name):
        self.id = id
        self.username = username
        self.role_name = role_name

    def is_admin(self):
        return self.role_name == "Admin"

    def is_manager(self):
        return self.role_name == "Manager"

    def is_employee(self):
        return self.role_name == "Employee"
    

#### ADMIN

@role_required('Admin')
def admin_dashboard():
    # Fetch total users
    cur = mysql.connection.cursor()
    cur.execute("SELECT COUNT(id) FROM users")
    total_users = cur.fetchone()[0]

    # Fetch total files uploaded
    cur.execute("SELECT COUNT(id) FROM files")
    total_files = cur.fetchone()[0]
    
    return render_template('admin_dashboard.html', total_users=total_users, total_files=total_files)

# Route to view users
@app.route('/Admin/view_users')
@role_required('Admin')
def view_users():
    print(f"Session: {session}")
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT id, username, role_name FROM users")
    users = cur.fetchall()
    return render_template('view_users.html', users=users)

# Route to change user role
@app.route('/admin/change_user_role/<int:user_id>', methods=['GET', 'POST'])
@role_required('Admin')
def change_user_role(user_id):
    if request.method == 'POST':
        new_role = request.form['role_name']
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET role_name = %s WHERE id = %s", (new_role, user_id))
        mysql.connection.commit()
        flash('User role updated successfully!')
        return redirect(url_for('view_users'))
    
    return render_template('change_role.html', user_id=user_id)

# Route to delete user
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@role_required('Admin')
def delete_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    mysql.connection.commit()
    flash('User deleted successfully!')
    return redirect(url_for('view_users'))

