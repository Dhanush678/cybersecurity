from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import socket
import pem
testerID={
    "0x0a":b"x04x34x45x32",
    "0x0b":b"3x45x67x3x2x3",
    "0x0c":b"\x55\01\00\00\00\00",
    "0x0d":b"\x68\01\00\00\00\00"
}

UDS_COMMANDS = {
    "0x01": "\x10\x01\x00\x03\x00\x00",
    "0x02": "\x01\x02\x03\x03\x00",
    "0x11": "\x55\x01\x00\x00\x00\x00",
    "0x27": "\x67\x01\x00\x00\x00\x00",
    "0x28": "\x68\x01\x00\x00\x00\x00",
}


private_key = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=default_backend()
)
public_key = private_key.public_key()

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("10.24.51.56", 12345))
server_socket.listen(1)

print("Server started. Waiting for client connection...\n")

while True:
    client_socket, address = server_socket.accept()
    print("Client connected:", address)

    client_socket.sendall(public_pem)

    encrypted_service_id = client_socket.recv(4096)
    print("Recieved Data\n\n")
    print(encrypted_service_id)

    decrypted_service_id = public_key.decrypt(
        encrypted_service_id,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    def handle_uds_command(command):
        if command in testerID:
            response = testerID[command]
            print("Verifying\n")

        else:
            response = b"\x7F" 
            print("Tester not verified\n") 
            client_socket.close()# Negative response
            exit()

        return response

    print("Decrypted Service ID:", decrypted_service_id.decode(),"\n")
    command = client_socket.recv(1024)
    print("Received command:", decrypted_service_id.decode(),"\n")
    
    command = decrypted_service_id.decode()

    response = handle_uds_command(command)
    client_socket.sendall(response)
    


    print("Verification:Verified with service ID", decrypted_service_id.decode(),"\n")
    
    challenge=response.decode()




        
    private_key2 = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key2 = private_key2.public_key()

    public_pem2 = public_key2.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    print("challege:-",response)


    encrypty_challenge = public_key2.encrypt(
    challenge.encode('utf-8'),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
    
    client_socket.close()
    print("Generating challenge and encrypting\n\n")
    print(encrypty_challenge)
    pki = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    pki.bind(("169.254.140.221", 5555))
    pki.listen(1)
  

    while True:
        pki_socket, address = pki.accept()
        print("Client connected: ", address)

        pki_socket.sendall(public_pem2)
        pki_socket.sendall(encrypty_challenge)
        signature=pki_socket.recv(2048)
        print(signature)
        public_sign=pki_socket.recv(2048)
        hashed_challege=bytes(signature)
        public_key3 = serialization.load_pem_public_key(
    public_sign, backend=default_backend())

      
        def generate_signature(data, private_key_path):
            with open(public_key3, "rb") as key_file:
                public_key3 = pem.parse(key_file.read())[0].as_bytes()
                public_key3 = rsa.RSAPrivateKey.from_pem(public_key3)
            signature = public_key3.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return signature
        print("Signature:\n\n", signature.hex())
        print("\n")
        def Print_logg():
            print("Printing logs:-\n")
            print("Encrypted Service ID:\n",encrypted_service_id,"\n")
            print("decrypted service ID:-\n",decrypted_service_id)
            print("Generated Challenge:\n",challenge)
            print("Encrypted Challenge:-\n",encrypty_challenge)
            print("Digitally Signed \n",signature)
            print("Hashed Challenge\n",hashed_challege)

        if hashed_challege is signature:
            print("\n")
            print("Verified Succesfully")
            Print_logg()

        else:
            print("\n")

            print("Failed")
            pki_socket.close()
        def Print_logg():
            print("\n\n")
            print("\t\t\tPrinting loggs:-\n")
            print("\t\t\tEncrypted Service ID:\n",encrypted_service_id,"\n")
            print("\t\t\tdecrypted service ID:-\n",decrypted_service_id)
            print("\t\t\tGenerated Challenge:\n",challenge)
            print("\t\t\tEncrypted Challenge:-\n",encrypty_challenge)
            print("\t\t\tDigitally Singed \n",signature)
            print("\t\t\tHashed Challenge\n",hashed_challege)


            

    
        


        
