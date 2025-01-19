# SafeDocs: Secure File Management 

SafeDocs is a reliable and intuitive application designed to provide secure file encryption, sharing, and management. With a strong emphasis on privacy and ease of use, it offers features such as role-based access control, team collaboration, and file encryption using advanced security algorithm.

## Features

- **Role-Based Access Control (RBAC)**: Admins, Managers, and Employees have specific privileges.
- **File Encryption and Decryption**: Secure your files with RSA encryption.
- **Team Sharing**: Managers can share files with their team members.
- **File Management**: Upload, view, download, and delete files.
- **Cross-Platform Desktop App**: Packaged as an executable for seamless use.

## Technology Stack

- **Backend**: Flask (Python Framework)
- **Frontend**: Electron with HTML, CSS, and JavaScript
- **Database**: MySQL
- **Encryption**: RSA Algorithm
- **Development Tools**: Python, VS Code

## Installation Guide

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Anupamatilak21/Secure_File_Management.git
   
   cd Secure_File_Management

2. **Set up environment**;

- Install Python 

- Create a virtual environment:
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

3. **Install Dependencies**:

pip install -r requirements.txt

4. **Configure Database**:

- Set up  a MYSQL database
- Run the schema.sql file to create tables.
- Update db.py with your database credentials.




