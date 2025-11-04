# 🛡️ SafeDocs – Secure File Management System

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-Framework-lightgrey?logo=flask&logoColor=black)](https://flask.palletsprojects.com/)
[![MySQL](https://img.shields.io/badge/Database-MySQL-blue?logo=mysql&logoColor=white)](https://www.mysql.com/)
[![Contributions Welcome](https://img.shields.io/badge/Contributions-Welcome-brightgreen.svg)](https://github.com/Anupamatilak21/Secure_File_Management/issues)

SafeDocs is a reliable and intuitive application designed to provide **secure file encryption, sharing, and management**.  
With a strong emphasis on **privacy, access control, and usability**, it ensures that files remain protected while enabling seamless collaboration among users.

---
## 🚀 Features

- 🔐 **Role-Based Access Control (RBAC)** – Admins, Managers, and Employees have specific privileges.  
- 🗂️ **File Encryption & Decryption** – Safeguard files using **RSA encryption**.  
- 🤝 **Team Sharing** – Managers can securely share files with their team members.  
- 📁 **File Management** – Upload, view, download, and delete files effortlessly.  
- 💻 **Cross-Platform Support** – Runs smoothly as a desktop application.  

---

## 🧩 Technology Stack

| Component | Technology |
|------------|-------------|
| **Backend** | Flask (Python Framework) |
| **Frontend** | HTML, CSS, JavaScript |
| **Database** | MySQL |
| **Encryption** | RSA Algorithm |
| **Development Tools** | Python, VS Code |

---

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

5. **Configure Database**:
- Set up  a MYSQL database
- Run the schema.sql file to create tables.
- Update db.py with your database credentials.

5. **Run :**
   
         python app.py

---

## 🧠 Usage

1. **Login or Register** as a user.  
2. Based on your role:  
   - **Admin**: Manage all users and files.  
   - **Manager**: Upload, view, share, or delete files within your team.  
   - **Employee**: Upload and view shared files.  
3. All uploaded files are **automatically encrypted** before being stored.  
4. Files can be **decrypted** and downloaded securely when needed.

---

## 🔒 Security Highlights

- Implements **RSA encryption** for file security.  
- Protects user data with **role-based access control (RBAC)**.  
- Ensures **end-to-end confidentiality** during file sharing.  

---

## 🔮 Future Scope

- Integration of **Hybrid Encryption (AES + RSA)** for faster encryption and decryption.  
- Addition of **Data Visualization** dashboards for uploaded file analytics.  
- Enhanced **audit logging** and **activity tracking**.  
- Cloud integration for scalable storage options.
---



