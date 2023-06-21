import socket

# Get the hostname of the current machine
hostname = socket.gethostname()

# Get the IP address of the current machine
ip_address = socket.gethostbyname(hostname)

print("Hostname:", hostname)
print("IP Address:", ip_address)
