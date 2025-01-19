-- Create the 'roles' table to define user roles (Admin, Manager, Employee)
CREATE TABLE roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(255) NOT NULL
);

-- Create the 'users' table to store user information
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    role_name VARCHAR(255) DEFAULT 'Employee',
    role_id INT,
    manager_id INT,
    FOREIGN KEY (role_id) REFERENCES roles(id),  -- Assuming 'roles' table exists
    FOREIGN KEY (manager_id) REFERENCES users(id)  -- Self-referencing foreign key for manager
);

-- Create the 'files' table to store file details
CREATE TABLE files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    filepath VARCHAR(255) NOT NULL,
    encryption_method VARCHAR(20) NOT NULL,
    encryption_key VARCHAR(512),
    iv VARCHAR(255),
    private_key TEXT,
    user_id INT NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    file_size_before INT NOT NULL,
    file_size_after INT NOT NULL,
    encryption_time FLOAT NOT NULL,
    uploaded_by VARCHAR(255),
    shared_with_team TINYINT(1) DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
