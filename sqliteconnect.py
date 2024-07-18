import nmap
import psutil
import sqlite3

class Network(object):
    def __init__(self, ip=''):
        ip = input("Please enter the IP (default is 192.168.1.1/192.168.0.1): ")
        self.ip = ip

    def networkscanner(self):
        if len(self.ip) == 0:
            network = '192.168.1.1/24'
        else:
            network = self.ip + '/24'
        print("Scanning the network...")

        nm = nmap.PortScanner()
        nm.scan(hosts=network, arguments='-sP')  # Perform a ping scan to get more detailed info
        hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
        
        for host, status in hosts_list:
            try:
                hostname = nm[host].hostname()
                if not hostname:
                    hostname = 'Unknown'
            except KeyError:
                hostname = 'Unknown'

            print("Host: {}\tStatus: {}\tHostname: {}".format(host, status, hostname))
            self.get_host_traffic(host, status, hostname)

    def get_host_traffic(self, host, status, hostname):
        print(f"Capturing overall network traffic (interface level):")
        net_io = psutil.net_io_counters(pernic=False)
        print(f"Bytes Sent: {net_io.bytes_sent}, Bytes Received: {net_io.bytes_recv}")

        # Call the insert_data_into_database function
        insert_data_into_database(host, status, hostname)

        # Call the scan_open_ports function
        open_ports = self.scan_open_ports(host)
        print(f"Open Ports for {host}: {open_ports}")
        insert_ports_into_database(host, open_ports)

    def scan_open_ports(self, host):
        nm = nmap.PortScanner()
        nm.scan(host, '1-1024')  # Scan ports from 1 to 1024
        open_ports = []

        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port]['name']
                open_ports.append((port, state, service))

        return open_ports

def insert_data_into_database(host, status, hostname):
    # Connect to the database (or create it if it doesn't exist)
    connection = sqlite3.connect('sqlite20.db')

    # Create a cursor object to execute SQL commands
    cursor = connection.cursor()

    # Drop the existing 'users' table if it exists
    cursor.execute('DROP TABLE IF EXISTS users')

    # SQL command to create a table if it doesn't exist
    create_table_query = '''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT NOT NULL,
        status TEXT,
        hostname TEXT
    );
    '''

    # Execute the SQL command
    cursor.execute(create_table_query)

    # SQL command to insert data into the 'users' table
    insert_query = """
    INSERT INTO users (host, status, hostname)
    VALUES (?, ?, ?)
    """

    # Execute the SQL command with the data
    cursor.execute(insert_query, (host, status, hostname))

    # Commit the changes
    connection.commit()

    # Close the connection
    connection.close()

    print("Data inserted successfully.")

def insert_ports_into_database(host, open_ports):
    # Connect to the database (or create it if it doesn't exist)
    connection = sqlite3.connect('sqlite12.db')

    # Create a cursor object to execute SQL commands
    cursor = connection.cursor()

    # SQL command to create a table if it doesn't exist
    create_table_query = '''
    CREATE TABLE IF NOT EXISTS ports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT NOT NULL,
        port INTEGER,
        state TEXT,
        service TEXT
    );
    '''

    # Execute the SQL command
    cursor.execute(create_table_query)

    # SQL command to insert data into the 'ports' table
    insert_query = """
    INSERT INTO ports (host, port, state, service)
    VALUES (?, ?, ?, ?)
    """

    # Execute the SQL command with the data
    for port, state, service in open_ports:
        cursor.execute(insert_query, (host, port, state, service))

    # Commit the changes
    connection.commit()

    # Close the connection
    connection.close()

    print("Open ports data inserted successfully.")

# Example usage:
network = Network()
network.networkscanner()
