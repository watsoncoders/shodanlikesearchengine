import mysql.connector
import subprocess
import json
import geoip2.database
from datetime import datetime

# MySQL connection details
db_config = {
    'host': 'localhost',
    'user': 'your_user',
    'password': 'your_password',
    'database': 'your_database'
}

# Path to GeoIP database
geoip_db_path = '/path/to/GeoLite2-City.mmdb'  # Update with your GeoIP path

def insert_into_db(data):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()

    query = """
    INSERT INTO device_info (
        ip_address, open_ports, service_name, service_version, os_name, os_version, 
        device_type, http_title, http_status_code, web_technologies, ssl_info, 
        vulnerabilities, country, city, isp, scan_time
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    cursor.execute(query, (
        data['ip_address'], data['open_ports'], data['service_name'], data['service_version'],
        data['os_name'], data['os_version'], data['device_type'], data['http_title'],
        data['http_status_code'], data['web_technologies'], data['ssl_info'],
        data['vulnerabilities'], data['country'], data['city'], data['isp'], datetime.now()
    ))

    conn.commit()
    conn.close()

def geoip_lookup(ip):
    with geoip2.database.Reader(geoip_db_path) as reader:
        try:
            response = reader.city(ip)
            country = response.country.name
            city = response.city.name
            isp = response.traits.isp
            return country, city, isp
        except Exception as e:
            return "Unknown", "Unknown", "Unknown"

def parse_zgrab_output(output_file):
    with open(output_file, 'r') as file:
        results = json.load(file)

    for result in results:
        ip = result.get('ip', 'Unknown')
        service_name = result.get('data', {}).get('http', {}).get('server', 'Unknown')
        http_title = result.get('data', {}).get('http', {}).get('result', {}).get('response', {}).get('headers', {}).get('Title', 'Unknown')
        # Add other fields as necessary

        country, city, isp = geoip_lookup(ip)

        data = {
            'ip_address': ip,
            'open_ports': '80,443',  # Example ports, replace with real data
            'service_name': service_name,
            'service_version': 'Unknown',  # Add logic to get this from the result
            'os_name': 'Unknown',  # You can add OS detection with additional tools
            'os_version': 'Unknown',
            'device_type': 'Unknown',
            'http_title': http_title,
            'http_status_code': 200,  # Add logic to get the real status code
            'web_technologies': 'Unknown',  # Add logic to detect web technologies
            'ssl_info': 'Unknown',  # Add logic to get SSL info from HTTPS scans
            'vulnerabilities': 'Unknown',  # Add Nuclei results here
            'country': country,
            'city': city,
            'isp': isp,
        }

        insert_into_db(data)

if __name__ == "__main__":
    # Run Zgrab on HTTP services
    subprocess.run("zgrab2 http --port 80 --input-file=zmap_output.csv --output-file=http_results.json", shell=True)

    # Parse and insert Zgrab results into DB
    parse_zgrab_output('http_results.json')
