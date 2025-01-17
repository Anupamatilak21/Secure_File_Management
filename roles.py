from functools import wraps
from flask import redirect, url_for, session,render_template,flash,request
from flask_login import current_user, UserMixin
from db import mysql, app
import MySQLdb


def role_required(*required_role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if 'user_id' not in session:
                flash("Please log in to access this page.")
                return redirect(url_for("login"))
            if session.get('role_name').lower() not in [role.lower() for role in required_role]:
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
    
    cur.close()

    return render_template('admin_dashboard.html', total_users=total_users, total_files=total_files)

# Route to view users - FOR BOTH ADMIN AND MANAGER
@app.route('/view_users')
@role_required('Admin','Manager')
def view_users():
    print(f"Session: {session}")
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if session['role_name'] == 'Admin':
        cur.execute("SELECT id, username, role_name FROM users")
    elif session['role_name'] == 'Manager':
        manager_id = session['user_id'] 
        cur.execute("SELECT id, username, role_name FROM users WHERE manager_id = %s", (manager_id,))
    
    users = cur.fetchall()
    cur.close()
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

#### MANAGER

@role_required('Manager') 
def manager_dashboard():
    
    manager_id = session['user_id']

    cur = mysql.connection.cursor()

    cur.execute("SELECT COUNT(*) FROM users WHERE manager_id = %s", (manager_id,))
    total_team_members = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*) FROM files 
        WHERE uploaded_by = (SELECT username FROM users WHERE id = %s)
        OR uploaded_by IN (SELECT username FROM users WHERE manager_id = %s)
    """, (manager_id, manager_id))
    total_team_files = cur.fetchone()[0]

    cur.close()
    print(f"Total Team Members: {total_team_members}")
    print(f"Total Files Uploaded: {total_team_files}")


    return render_template(
        'manager_dashboard.html',total_team_members=total_team_members,total_team_files=total_team_files
    )

#### EMPLOYEE

@role_required('Employee')
def employee_dashboard():
    if 'user_id' not in session:
        flash("Please log in to access this page.")
        return redirect(url_for('login'))

    role_name = session['role_name']
    
    # Ensure only employees can access this page
    if role_name != 'Employee':
        flash("You do not have permission to view this page.")
        return redirect(url_for('dashboard'))  # Redirect to a general dashboard or home page

    return render_template('employee_dashboard.html')




