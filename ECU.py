from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import socket
import ssl
import pem
import os as os
import time
import wmi
import datetime
now = datetime.datetime.now()

tester_unit=0
testerID={
    "002702":b"x04x34x45x32",
    "002734":b"3x45x67x3x2x3",
    "002733":b"\x55\01\00\00\00\00",
    "002731":b"\x68\01\00\00\00\00"
}
verified_tester=[
     b"00456",b"00455"
     
]


positve_Id=b"02023"
negative_Id=b"07f"


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
def Print_logg():
            print("Printing logs:-\n")
            print(str(now),"Encrypted Service ID:\n",encrypted_service_id,"\n")
            print(str(now),"decrypted service ID:-\n",decrypted_service_id)
           




server_socke = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socke.bind(("localhost", 12345))
server_socke.listen(1)

print("Server started. Waiting for client connection...\n")

while True:
    client_socket, address = server_socke.accept()
    print("Client connected:", address)
    seed_key=b"0064"

    client_socket.sendall(public_pem)
    client_socket.sendall(seed_key)


    encrypted_service_id = client_socket.recv(4096)
    print("Recieved Data\n\n")
    print(encrypted_service_id)

    decrypted_service_id = private_key.decrypt(
        encrypted_service_id,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    if decrypted_service_id in verified_tester:
        print("Tester verified ")
        os.system('cls' if os.name=='nt' else 'clear')
        print("categories")
        dt=input("1-->Enigne Temperature \t\t2-->Airbag System\t\t3-->Secure_Logg\nEnter: ")
        while 1:
            if dt == "1":
                    print("90 celsius ")
                    client_socket.sendall(positve_Id)
                    break
            if dt=="2":
                    print("Analysing.....")
                    print("ERRROR:42423")
                    client_socket.sendall(negative_Id)
                    break
            if dt=="3":
                    print("Printing loggs")
                    Print_logg()
                    break
            


    def handle_uds_command(command):
        if command in testerID:
            response = testerID[command]
            print("Verifying\n")

        else:
            response = b"\x7F" 
            print(response)
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
    print("\nWaiting for PKI Server......")
    pki = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    pki.bind(("localhost", 5555))
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
        pki_socket.close()
        server_socke.close()
       
        


    

      
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
        pki_socket.close()

        def verify():
            if hashed_challege is signature:
                                print("\n")
                                print("Verified Succesfully")
                                text=input("\nTester authorized (Press enter )")
                                if(text==""):
                                    os.system('cls' if os.name=='nt' else 'clear')
                                verified_tester.append(decrypted_service_id)
                                print("Connecting to ECU....")
                                return tester_unit==1
            else:
                                return tester_unit==0

        verify()
