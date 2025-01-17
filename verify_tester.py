from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import socket
import time
import ssl

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))


public_pem = client_socket.recv(4096)


public_key = serialization.load_pem_public_key(
    public_pem, backend=default_backend())

service_id = "04A"

encrypted_service_id = public_key.encrypt(
    service_id.encode('utf-8'),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

try:
    client_socket.sendall(encrypted_service_id)
    print("Service sent:", service_id)
    print("encrpted data:", encrypted_service_id)


except:
    print("Failed to send Service ID")

print("verifying please wait....")
seed=client_socket.recv(1024)
print("Obtinaing seeds....\n\n")
print("recieved seeds:")
print(seed)


client_socket.close




