import os
from flask import Flask, render_template, request, redirect, url_for, flash , send_file, session
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad , unpad 
from Crypto.Random import get_random_bytes
from werkzeug.security import check_password_hash , generate_password_hash
from werkzeug.utils import secure_filename
from flask_mysqldb import MySQL
import mysql.connector
import MySQLdb.cursors 

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



@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    else:
        return render_template('home.html')  
    
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in to access the dashboard.")
        return redirect(url_for('login'))
    
    return render_template('dashboard.html' , username = session.get('username'))

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

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Logged out successfully.')
    return redirect(url_for('home'))

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

            user_id = session['user_id']  #Get the user_id of the logged-in user
            
            cur = mysql.connection.cursor()
            cur.execute(
                "INSERT INTO files (filename, filepath, encryption_key, iv ,user_id) VALUES (%s, %s, %s, %s, %s)",(filename, encrypted_filepath , key.hex(), iv.hex(), user_id)
            )
            mysql.connection.commit()
            cur.close()

            flash(f"File {filename} uploaded successfully !")
            return redirect(url_for('upload'))
        
    return render_template('upload.html')


@app.route('/files')
def files():

    if 'user_id' not in session:
        flash("Please log in to access this page.")
        return redirect(url_for('login'))
    
    user_id = session['user_id'] 

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM files WHERE user_id = %s", (user_id,))
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

        try:
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

            #return send_file(decrypted_filepath, as_attachment=True, download_name=decrypted_filename)
            flash(f"File {decrypted_filename} has been downloaded successfully!")
            return redirect(url_for('files'))

        except Exception as e:
            flash(f"Error during decryption: {str(e)}")
            return redirect(url_for('files'))
    
    else:
        flash('File not found.')
        return redirect(url_for('files'))

    

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


