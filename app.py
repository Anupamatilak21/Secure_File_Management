import os
from db import app, mysql
from flask import Flask, render_template, request, redirect, url_for, flash , send_file, session, jsonify
from Crypto.Cipher import AES , DES 
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad , unpad 
from Crypto.Random import get_random_bytes
from werkzeug.security import check_password_hash , generate_password_hash
from werkzeug.utils import secure_filename
from flask_mysqldb import MySQL
import MySQLdb
import MySQLdb.cursors 
import time
from flask_login import LoginManager, login_user, current_user, logout_user
from roles import User , role_required
from roles import admin_dashboard,view_users, change_user_role, delete_user
from roles import manager_dashboard,employee_dashboard

# UPLOADING Folder
app.config['UPLOAD_FOLDER'] ='uploads'
app.secret_key = 'your_secret_key'

# Checking the uploading folder existence 
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

login_manager = LoginManager(app)

### Role Based Access

@login_manager.user_loader
def load_user(user_id):
    # Fetch user details by ID
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, username, role_name FROM users WHERE id = %s", (user_id,))
    user_data = cur.fetchone()
    cur.close()

    if user_data:
        return User(id=user_data[0], username=user_data[1], role_name=user_data[2])
    return None

### HOME

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    else:
        return render_template('home.html')  
    

### DASHBOARD
    

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in to access the dashboard.")
        return redirect(url_for('login'))
    
    role = session.get('role_name')

    if role == 'Admin':
        return render_template('admin_dashboard.html')  # Admin-specific dashboard
    elif role == 'Manager':
        return render_template('manager_dashboard.html')  # Manager-specific dashboard
    elif role == 'Employee':
        return render_template('employee_dashboard.html')  # Employee-specific dashboard
    else:
        flash("Invalid role.")
        return render_template('login.html' , username = session.get('username'))


### LOGIN EXISTNG USERS


@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Query to fetch user details from the database
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT id, password_hash, role_name, manager_id FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()

        if user and check_password_hash(user['password_hash'], password):
            # Store user ID in the session for further reference
            session['user_id'] = user['id']
            session['username'] = username
            session['role_name'] = user['role_name']
            session['manager_id'] = user['manager_id'] # Store manager_id for employees
            flash('Login successful !')
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password .")

    return render_template('login.html')


### LOGOUT FEATURE


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Logged out successfully.')
    return redirect(url_for('home'))


### REGISTERING NEW USERS


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role_name = request.form.get('role_name', 'Employee')
        manager_id = request.form.get('manager_id') if role_name == 'Employee' else None

        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM users WHERE username = %s", (username,))
        existing_user = cur.fetchone()

        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('register'))
        
        # Fetching the role_id based on the role_name
        cur.execute("SELECT id FROM roles WHERE role_name = %s", (role_name,))
        role = cur.fetchone()
        role_id = role[0] if role else None

        if not role_id:
            flash("Invalid role selected.")
            return redirect(url_for('register'))
        
        #HAshing password before storing
        hashed_password = generate_password_hash(password)

        cur.execute(
            "INSERT INTO users (username, password_hash, role_id, role_name, manager_id) VALUES (%s , %s, %s , %s , %s)" , (username, hashed_password, role_id, role_name, manager_id)
        )
        mysql.connection.commit()
        cur.close()

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    
    # For GET request, fetch the list of managers
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, username FROM users WHERE role_name = 'Manager'")
    managers = cur.fetchall()
    cur.close()

    print(managers)

    return render_template('register.html', managers=managers)


### UPLOAD FEATURE


@app.route('/upload', methods= ['GET','POST'])
def upload():

    if 'user_id' not in session:
        flash("Please log in to access this page.")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['file']
        encryption_method = request.form.get('encryption_method')  # 'AES', 'DES', or 'RSA'

        if file.filename == '':
            flash('No selected file. Please choose a file to upload.')
            return redirect(request.url)
        
        if file and encryption_method:
            file_data = file.read()
            filename = secure_filename(file.filename)
            encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Variables declared
            key_data = None
            iv = None
            private_key = None
            file_size_before = len(file_data)
            file_size_after = None
            encryption_time = None

            try:
                start_time = time.time()
                '''
                if encryption_method == 'AES':
                    # AES Encryption
                    key_data = get_random_bytes(16)  # AES key: 16 bytes
                    cipher = AES.new(key_data, AES.MODE_CBC)
                    iv = cipher.iv
                    encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))

                elif encryption_method == 'DES':
                    # DES Encryption
                    key_data = get_random_bytes(8)  # DES key: 8 bytes
                    cipher = DES.new(key_data, DES.MODE_CBC)
                    iv = cipher.iv
                    encrypted_data = cipher.encrypt(pad(file_data, DES.block_size))
                '''
                if encryption_method == 'RSA':
                    # RSA Encryption
                    key_pair = RSA.generate(2048)  # Generate RSA keys
                    public_key = key_pair.publickey()
                    private_key = key_pair.export_key().decode()  # PEM format
                    
                    # Generate AES key for symmetric encryption (AES-256)
                    aes_key = get_random_bytes(32)  # AES-256 key size
                    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
                    iv = cipher_aes.iv  # AES initialization vector (IV)

                    # Encrypt the file data using AES (symmetric encryption)
                    encrypted_data = cipher_aes.encrypt(pad(file_data, AES.block_size))

                    # Encrypt the AES key with RSA
                    cipher_rsa = PKCS1_OAEP.new(public_key)
                    encrypted_aes_key = cipher_rsa.encrypt(aes_key)  # Encrypt the AES key with RSA
                    key_data = encrypted_aes_key    #Giving a generic name key data so that it is easier to add into the databse 

                    # Store the encrypted file and encrypted AES key (along with the IV)
                    filename = secure_filename(file.filename)
                    encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                else:
                    flash('Invalid encryption method selected.')
                    return redirect(request.url)

                encryption_time = time.time() - start_time
                file_size_after = len(encrypted_data)

                # Save encrypted file
                with open(encrypted_filepath, 'wb') as f:
                    f.write(encrypted_data)

                user_id = session['user_id']  #Get the user_id of the logged-in user
                uploaded_by = session['username']
                
                cur = mysql.connection.cursor()
                cur.execute(
                    "INSERT INTO files (filename, filepath, encryption_key, iv, private_key, encryption_method, file_size_before, file_size_after, encryption_time, user_id, uploaded_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (filename,
                        encrypted_filepath,
                        key_data.hex() if key_data else None,
                        iv.hex() if iv else None,
                        private_key,
                        encryption_method,
                        file_size_before,
                        file_size_after,
                        encryption_time,
                        user_id,
                        uploaded_by
                    )
                )
                mysql.connection.commit()
                cur.close()

                flash(f"File {filename} uploaded successfully !")
                return redirect(url_for('upload'))
            
            except Exception as e:
                flash(f"Error during encryption: {e}")
                return redirect(request.url)
        
    return render_template('upload.html')


### FILE LISTING INTERFACE


@app.route('/files')
def files():

    if 'user_id' not in session:
        flash("Please log in to access this page.")
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    role_name = session['role_name'] 

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if role_name == 'Admin':
        cur.execute("SELECT id, filename, uploaded_at, encryption_method, file_size_before, encryption_time, file_size_after, uploaded_by, shared_with_team FROM files")
        uploaded_files = cur.fetchall()

    elif role_name == 'Manager':
        cur.execute("""SELECT id, filename, uploaded_at, encryption_method, file_size_before, encryption_time,file_size_after, uploaded_by, shared_with_team FROM files 
            WHERE user_id = %s OR user_id IN (SELECT id FROM users WHERE manager_id = %s)
            OR shared_with_team = TRUE
        """, (user_id, user_id))
        uploaded_files = cur.fetchall()

    else:        
        cur.execute("""SELECT id, filename, uploaded_at, encryption_method, file_size_before, encryption_time, file_size_after, uploaded_by, shared_with_team FROM files 
                    WHERE user_id = %s" OR shared_with_team = TRUE """, (user_id,))
        uploaded_files = cur.fetchall()
    
    cur.close()

    return render_template('files.html', files=uploaded_files)

### FILE SHARING FEATURE

@app.route('/update_share_status/<int:file_id>', methods=['POST'])
def update_share_status(file_id):
    
    data = request.get_json()
    shared_with_team = data.get('shared_with_team', False)  # Default to False if key is missing

    
    cur = mysql.connection.cursor()
    cur.execute("UPDATE files SET shared_with_team = %s WHERE id = %s", (shared_with_team, file_id))
    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "File share status updated successfully", "file_id": file_id})



### DOWNLOAD FEATURE


@app.route('/download/<int:file_id>')
def download(file_id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    #Fetching files and encryption data
    cur.execute("SELECT filepath, filename, encryption_key, iv, encryption_method, private_key FROM files WHERE id = %s", (file_id,))
    file_data = cur.fetchone()
    cur.close()

    if not file_data:
        flash('File not found')
        return redirect(url_for('files'))
    
    file_path = file_data['filepath']
    encryption_method = file_data['encryption_method']
    encryption_key_hex = file_data['encryption_key']
    iv_hex = file_data['iv']
    private_key_pem = file_data['private_key']

    if not file_path or not os.path.exists(file_path):
        flash('File path is invalid or the file does not exist.')
        return redirect(url_for('files'))   

        
    try:
        # Reading the encrypted file
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()   

        decrypted_data =None
        '''
        if encryption_method == 'AES':
            if not encryption_key_hex or not iv_hex:
                flash('Missing encryption key or IV for AES.')
                return redirect(url_for('files'))
            
            encryption_key = bytes.fromhex(encryption_key_hex)
            iv = bytes.fromhex(iv_hex)

            if len(encryption_key) != 16:
                flash('Invalid AES key length.')
                return redirect(url_for('files'))

            if len(iv) != 16:
                flash('Invalid AES IV length.')
                return redirect(url_for('files'))
            
            cipher = AES.new(encryption_key, AES.MODE_CBC,iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

        elif encryption_method == 'DES':
            if not encryption_key_hex or not iv_hex:
                flash('Missing encryption key or IV for DES.')
                return redirect(url_for('files'))

            encryption_key = bytes.fromhex(encryption_key_hex)
            iv = bytes.fromhex(iv_hex)

            if len(encryption_key) != 8:
                flash('Invalid DES key length.')
                return redirect(url_for('files'))

            if len(iv) != 8:
                flash('Invalid DES IV length.')
                return redirect(url_for('files'))

            cipher = DES.new(encryption_key, DES.MODE_CBC,iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), DES.block_size)

        '''
        if encryption_method == 'RSA':
            if not private_key_pem or not encryption_key_hex or not iv_hex:
                flash('Missing private key, encryption key, or IV for RSA decryption.')
                return redirect(url_for('files'))
            
            private_key = RSA.import_key(private_key_pem)
            encrypted_aes_key = bytes.fromhex(encryption_key_hex)
            iv = bytes.fromhex(iv_hex) 
            cipher_rsa = PKCS1_OAEP.new(private_key)
            decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)  # encrypted AES key from DB

            # Decrypt the file using the decrypted AES key
            cipher_aes = AES.new(decrypted_aes_key, AES.MODE_CBC,iv)  # iv is from DB
            decrypted_data = unpad(cipher_aes.decrypt(encrypted_data), AES.block_size)

        else:
            flash('Unsupported encryption method.')
            return redirect(url_for('files')) 

        decrypted_filename = f"decrypted_{os.path.basename(file_path)}"
        decrypted_filepath = os.path.join('uploads', decrypted_filename)

        with open(decrypted_filepath, 'wb') as f:
            f.write(decrypted_data)

        #return send_file(decrypted_filepath, as_attachment=True, download_name=decrypted_filename)
        flash(f"File {decrypted_filename} has been downloaded successfully!")
        return redirect(url_for('files'))

    except ValueError as e:
        flash(f"Error during decryption: {str(e)}")
        return redirect(url_for('files'))


### DELETE FEATURE

def is_manager_of_user(manager_id, employee_id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT id FROM users WHERE manager_id = %s AND id = %s", (manager_id, employee_id))
    result = cur.fetchone()
    return result is not None


@app.route('/delete/<int:file_id>', methods=['POST'])
def delete(file_id):
    if 'user_id' not in session:
        flash("Please log in to access this page.")
        return redirect(url_for('login'))

    user_id = session['user_id']
    role_name = session['role_name']

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT filepath, filename, uploaded_by, user_id FROM files WHERE id = %s", (file_id,))
    file_data = cur.fetchone()

    if file_data:
        file_path = file_data['filepath']
        filename = file_data['filename']
        uploaded_by = file_data['uploaded_by']
        file_owner_id = file_data['user_id']

        # Check permissions based on the user's role
        if role_name == 'Admin' or (role_name == 'Manager' and (uploaded_by == session['username'] or is_manager_of_user(user_id, file_owner_id))) or (role_name == 'Employee' and file_owner_id == user_id):
            try:
                # Remove the file from the server
                if os.path.exists(file_path):
                    os.remove(file_path)
                # Optionally remove decrypted file
                decrypted_filename = f"decrypted_{os.path.basename(file_path)}"
                decrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
                if os.path.exists(decrypted_filepath):
                    os.remove(decrypted_filepath)

                # Delete file record from the database
                cur.execute("DELETE FROM files WHERE id = %s", (file_id,))
                mysql.connection.commit()
                flash(f'File {filename} deleted successfully.')
            except Exception as e:
                flash(f'Error deleting file: {e}')
        else:
            flash("You do not have permission to delete this file.")
    else:
        flash('File not found.')

    cur.close()
    return redirect(url_for('files'))


### ROLE-Management

@app.route('/admin/dashboard')
@role_required('Admin')
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/manager/files')
@role_required('Manager')
def manager_files():
    return render_template('manager_dashboard.html')

@app.route('/employee/tasks')
@role_required('Employee')
def employee_tasks():
    return render_template('employee_dashboard.html')

#### ADMIN 
app.add_url_rule('/admin/dashboard', 'admin_dashboard', admin_dashboard)
app.add_url_rule('/view_users', 'view_users', view_users)
app.add_url_rule('/admin/change_user_role/<int:user_id>', 'change_user_role', change_user_role)
app.add_url_rule('/admin/delete_user/<int:user_id>', 'delete_user', delete_user)

#### MANAGER
app.add_url_rule('/manager/dashboard', 'manager_dashboard', manager_dashboard)

#### EMPLOYEE
app.add_url_rule('/employee/dashboard','employee_dashboard', employee_dashboard)


if __name__ == "__main__":
    app.run(debug=True)


