CREATE TABLE device_info (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    open_ports VARCHAR(100),
    service_name VARCHAR(255),
    service_version VARCHAR(255),
    os_name VARCHAR(255),
    os_version VARCHAR(255),
    device_type VARCHAR(255),
    http_title VARCHAR(255),
    http_status_code INT,
    web_technologies TEXT,
    ssl_info TEXT,
    vulnerabilities TEXT,
    country VARCHAR(100),
    city VARCHAR(100),
    isp VARCHAR(100),
    scan_time DATETIME
);
