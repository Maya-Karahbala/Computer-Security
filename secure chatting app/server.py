import socket 
import threading

HEADER = 64
PORT = 5054
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "d"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
cleints=[]

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")

    connected = True
    conn.send("please enter client id number ".encode(FORMAT))
    #when cleint is connected he asked to enter id number of cleint to communicate with
    #each msg is sended as message length then message it self to be bufferd 
    msg_length = conn.recv(HEADER).decode(FORMAT)
    if msg_length:
            msg_length = int(msg_length)
    msg = conn.recv(msg_length).decode(FORMAT)
    newCon=list(filter(lambda d: d['id']==int(msg),cleints))[0]['socket']
    print("---")
    print(newCon)
    newCon.send(msg.encode(FORMAT))
    print("requested cleint number is :"+msg)
    # if cleint with entered id number is verified start the session between them
    while connected:
        
        msg_length = conn.recv(HEADER).decode(FORMAT)
        if msg_length:
            msg_length = int(msg_length)
            msg = conn.recv(msg_length).decode(FORMAT)
            if msg == DISCONNECT_MESSAGE:
                connected = False
                return

            newCon.send(msg.encode(FORMAT))
            print(msg)

            

    conn.close()
        

def start():
    idCounter=0
    server.listen()
    print(f"[LISTENING] Server is listening on {SERVER}")
    while True:
        conn, addr = server.accept()
        cleints.append({"socket":conn, "addres":addr[1],"id":idCounter})
        print(f"new cleint {idCounter}")
        idCounter+=1
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
       


print("[STARTING] server is starting...")
start()
