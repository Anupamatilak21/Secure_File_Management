from flask import Flask
from flask_mysqldb import MySQL

app = Flask(__name__)

# Configuration for MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'mysql@123'
app.config['MYSQL_DB'] = 'secure_file_sharing'

mysql = MySQL(app)

