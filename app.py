import os
from flask import Flask, render_template, request, redirect, url_for, flash , send_file, session
from Crypto.Cipher import AES , DES 
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad , unpad 
from Crypto.Random import get_random_bytes
from werkzeug.security import check_password_hash , generate_password_hash
from werkzeug.utils import secure_filename
from flask_mysqldb import MySQL
import mysql.connector
import MySQLdb.cursors 
import time

app = Flask(__name__)

'''
HARDCODED_USER = {
    'username' :'admin',
    'password' : generate_password_hash('pass123')
}
'''

# UPLOADING Folder
app.config['UPLOAD_FOLDER'] ='uploads'
#app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limiting file size to 16 MB
app.secret_key = 'your_secret_key'

# Checking the uploading folder existence 
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'mysql@123'
app.config['MYSQL_DB'] = 'secure_file_sharing'

mysql = MySQL(app)

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
    
    return render_template('dashboard.html' , username = session.get('username'))


### LOGIN EXISTNG USERS


@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Query to fetch user details from the database
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT id, password_hash FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()

        if user and check_password_hash(user['password_hash'], password):
            # Store user ID in the session for further reference
            session['user_id'] = user['id']
            session['username'] = username
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

        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM users WHERE username = %s", (username,))
        existing_user = cur.fetchone()

        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('register'))
        
        #HAshing password before storing
        hashed_password = generate_password_hash(password)

        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (%s , %s)" , (username, hashed_password)
        )
        mysql.connection.commit()
        cur.close()

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')


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
            encryption_key = None
            iv = None
            private_key = None
            file_size_before = len(file_data)
            file_size_after = None
            encryption_time = None

            try:
                start_time = time.time()
                if encryption_method == 'AES':
                    # AES Encryption
                    encryption_key = get_random_bytes(16)  # AES key: 16 bytes
                    cipher = AES.new(encryption_key, AES.MODE_CBC)
                    iv = cipher.iv
                    encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))

                elif encryption_method == 'DES':
                    # DES Encryption
                    encryption_key = get_random_bytes(8)  # DES key: 8 bytes
                    cipher = DES.new(encryption_key, DES.MODE_CBC)
                    iv = cipher.iv
                    encrypted_data = cipher.encrypt(pad(file_data, DES.block_size))

                elif encryption_method == 'RSA':
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
                
                cur = mysql.connection.cursor()
                cur.execute(
                    "INSERT INTO files (filename, filepath, encryption_key, iv, private_key, encryption_method, file_size_before, file_size_after, encryption_time, user_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (filename,
                        encrypted_filepath,
                        encryption_key.hex() if encryption_key else None,
                        iv.hex() if iv else None,
                        private_key,
                        encryption_method,
                        file_size_before,
                        file_size_after,
                        encryption_time,
                        user_id
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

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT id, filename, uploaded_at, encryption_method, file_size_before, encryption_time, file_size_after FROM files WHERE user_id = %s", (user_id,))
    uploaded_files = cur.fetchall()
    cur.close()

    return render_template('files.html', files=uploaded_files)


### DOWNLOAD FEATURE


@app.route('/download/<int:file_id>')
def download(file_id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    #Fetching files and encryption data
    cur.execute("SELECT filepath, filename, encryption_key, iv, encryption_method FROM files WHERE id = %s", (file_id,))
    file_data = cur.fetchone()
    cur.close()

    if not file_data:
        flash('File not found')
        return redirect(url_for('files'))
    
    file_path = file_data['filepath']
    encryption_method = file_data['encryption_method']
    encryption_key = file_data['encryption_key']
    iv = file_data['iv']

    if not file_path or not os.path.exists(file_path):
        flash('File path is invalid or the file does not exist.')
        return redirect(url_for('files'))   

        
    try:
        # Reading the encrypted file
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()   

        decrypted_data =None

        if encryption_method == 'AES':
            if not encryption_key or not iv:
                flash('Missing encryption key or IV for AES.')
                return redirect(url_for('files'))
            cipher = AES.new(bytes.fromhex(encryption_key), AES.MODE_CBC, bytes.fromhex(iv))
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

        elif encryption_method == 'DES':
            if not encryption_key or not iv:
                flash('Missing encryption key or IV for DES.')
                return redirect(url_for('files'))
            cipher = DES.new(bytes.fromhex(encryption_key), DES.MODE_CBC, bytes.fromhex(iv))
            decrypted_data = unpad(cipher.decrypt(encrypted_data), DES.block_size)

        elif encryption_method == 'RSA':
            if not private_key:
                flash('Missing private key for RSA decryption.')
                return redirect(url_for('files'))
            # Decrypt the AES key with RSA
            private_key = RSA.import_key(bytes.fromhex(private_key)) 
            cipher_rsa = PKCS1_OAEP.new(private_key)
            decrypted_aes_key = cipher_rsa.decrypt(bytes.fromhex(encryption_key))  # encrypted AES key from DB

            # Decrypt the file using the decrypted AES key
            cipher_aes = AES.new(decrypted_aes_key, AES.MODE_CBC, bytes.fromhex(iv))  # iv is from DB
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

    except Exception as e:
        flash(f"Error during decryption: {str(e)}")
        return redirect(url_for('files'))


### DELETE FEATURE


@app.route('/delete/<int:file_id>', methods=['POST'])
def delete(file_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT filepath, filename FROM files WHERE id = %s", (file_id,))
    file_data = cur.fetchone()

    if file_data:
        file_path = file_data['filepath']
        filename = file_data['filename']
        try:
            if os.path.exists(file_path):
                os.remove(file_path)  # Delete the file from the server

            decrypted_filename = f"decrypted_{os.path.basename(file_path)}"
            decrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
        
            if os.path.exists(decrypted_filepath):
                os.remove(decrypted_filepath)


            cur.execute("DELETE FROM files WHERE id = %s", (file_id,))
            mysql.connection.commit()
            flash(f'File {filename} deleted successfully.')
        except Exception as e:
            flash(f'Error deleting file: {e}')
    else:
        flash('File not found.')

    cur.close()
    return redirect(url_for('files'))


if __name__ == "__main__":
    app.run(debug=True)


