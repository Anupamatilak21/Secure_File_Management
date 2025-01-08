import os
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, flash , send_file, session
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad , unpad 
from Crypto.Random import get_random_bytes
from werkzeug.security import check_password_hash , generate_password_hash
from flask_mysqldb import MySQL
import mysql.connector
import MySQLdb.cursors 

app = Flask(__name__)

HARDCODED_USER = {
    'username' :'admin',
    'password' : generate_password_hash('pass123')
}

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


@app.route('/')
def home():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    else:
        return render_template('home.html')  
    
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash("Please log in to access the dashboard.")
        return redirect(url_for('login'))
    
    return render_template('dashboard.html')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == HARDCODED_USER['username'] and check_password_hash(HARDCODED_USER['password'],password):
            session['user'] = username
            flash('Login successful !')
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password .")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out successfully.')
    return redirect(url_for('home'))

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/upload', methods= ['GET','POST'])
def upload():

    if 'user' not in session:
        flash("Please log in to access this page.")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['file']

        if file.filename == '':
            flash('No selected file. Please choose a file to upload.')
            return redirect(request.url)
        
        if file:
            # Generating AES key and IV
            key = get_random_bytes(16)  # 16 bytes for AES-128
            cipher = AES.new(key, AES.MODE_CBC)
            iv = cipher.iv

            #Reading file data and encrypt 
            file_data = file.read()
            encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))

            # Save encrypted file
            filename = secure_filename(file.filename)
            encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            with open(encrypted_filepath, 'wb') as f:
                f.write(encrypted_data)

            cur = mysql.connection.cursor()
            cur.execute(
                "INSERT INTO files (filename, filepath, encryption_key, iv) VALUES (%s, %s, %s, %s)",(filename, encrypted_filepath , key.hex(), iv.hex())
            )
            mysql.connection.commit()
            cur.close()

            flash(f"File {filename} uploaded successfully !")
            return redirect(url_for('upload'))
        
    return render_template('upload.html')


@app.route('/files')
def files():

    if 'user' not in session:
        flash("Please log in to access this page.")
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM files")
    uploaded_files = cur.fetchall()
    cur.close()

    return render_template('files.html', files=uploaded_files)


@app.route('/download/<int:file_id>')
def download(file_id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    #Fetching files and encryption data
    cur.execute("SELECT filepath, filename, encryption_key, iv FROM files WHERE id = %s", (file_id,))
    file_data = cur.fetchone()
    cur.close()

    if file_data:
        file_path = file_data['filepath']
        encryption_key = bytes.fromhex(file_data['encryption_key'])  
        iv = bytes.fromhex(file_data['iv']) 

        if not file_path or not encryption_key or not iv:
            flash('Missing encryption key, IV, or file path.')
            return redirect(url_for('files'))

        # Decrypting file
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        # Create AES cipher using the encryption key and IV
        cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

        decrypted_filename = f"decrypted_{os.path.basename(file_path)}"
        decrypted_filepath = os.path.join('uploads', decrypted_filename)

        with open(decrypted_filepath, 'wb') as f:
            f.write(decrypted_data)

        return send_file(decrypted_filepath, as_attachment=True, download_name=decrypted_filename)
    
    else:
        flash('File not found.')
        return redirect(url_for('files'))

    

@app.route('/delete/<int:file_id>', methods=['POST'])
def delete(file_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT filepath FROM files WHERE id = %s", (file_id,))
    file_data = cur.fetchone()

    if file_data:
        file_path = file_data[0]
        try:
            if os.path.exists(file_path):
                os.remove(file_path)  # Delete the file from the server

            decrypted_filename = f"decrypted_{os.path.basename(file_path)}"
            decrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
        
            if os.path.exists(decrypted_filepath):
                os.remove(decrypted_filepath)


            cur.execute("DELETE FROM files WHERE id = %s", (file_id,))
            mysql.connection.commit()
            flash('File deleted successfully.')
        except Exception as e:
            flash(f'Error deleting file: {e}')
    else:
        flash('File not found.')

    cur.close()
    return redirect(url_for('files'))


if __name__ == "__main__":
    app.run(debug=True)


