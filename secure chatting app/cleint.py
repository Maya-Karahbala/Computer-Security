import socket
import threading
import random
from sympy import mod_inverse
from Crypto.Random import get_random_bytes

from Crypto import Random
from Crypto.Cipher import AES
import os
import os.path

from os import listdir
from os.path import isfile, join
import time
import struct
from hashlib import blake2b
from hmac import compare_digest
import pickle
import json
import base64
# constatnts for socket programming

HEADER = 64
PORT = 5054
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = ""
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)


#----------------------------------------------------------------------
# RSA codes for public private key generation
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num**0.5)+2, 2):
        if num % n == 0:
            return False
    return True

def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
    #n = pq
    n = p * q

    #Phi is the totient of n
    phi = (p-1) * (q-1)

    #Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(1, phi)

    #Use Euclid's Algorithm to verify that e and phi(n) are comprime
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    #Use Extended Euclid's Algorithm to generate the private key

    d = mod_inverse(e,phi)
    #Return public and private keypair
    #Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))

def encrypt(pk, plaintext):

    e, n = pk
     #c = m ^e mod  n
    #Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher = [(ord(char) ** e) % n for char in plaintext]
    #Return the array of bytes
    return cipher

def decrypt(pk, ciphertext):
#conver string to 5 digit list to meet deycrypt functiion requirements
    if type(ciphertext)==str:
        if type(ciphertext)==str:
            ciphertext=ciphertext[1:-1]
            ciphertext=list(map(lambda x: int(x), ciphertext.split(',')) )
        
    #Unpack the key into its components
    d, n = pk
    #Generate the plaintext based on the ciphertext and key using a^b mod m
    plain = [chr((char ** d) % n) for char in ciphertext]
    #Return the array of bytes as a string
    return ''.join(plain)


# in real word primes must be very very big
primes =list(filter(lambda x: is_prime(x),list(range(100, 150))))
p = random.choice(primes) 
#to prevent selecting same prime we delete it from the list
primes.remove(p)
q=random.choice(primes) 
public, private = generate_keypair(p, q)


#----------------------------------------------------------------------
# AES codes for encrypting chat messages

def pad( s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def encryptAES( message,key, key_size=128):
    message =pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    result=iv + cipher.encrypt(message)
    return int.from_bytes(result, "big")    

  

def decryptAES(ciphertext,key): 
    intCipher=int(ciphertext)
    ciphertext=bytearray(intCipher.to_bytes((intCipher.bit_length() + 7) // 8, 'big') or b'\0')
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

#----------------------------------------------------------------------
# socket programming

def send(msg):
    # send msg and itis length to server
    msg=str(msg)
    
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(message)
    
def listenToServer():
    while True:
        rsvMsg=client.recv(2048).decode(FORMAT)
        
        msg=str(decryptAES(str(rsvMsg),cleint2_symmtric_key))[2:-1]
        
        #resive hmac as array in string
        hmac=client.recv(2048).decode(FORMAT)
        inthmac=int(hmac)
        hmacByte=bytearray(inthmac.to_bytes((inthmac.bit_length() + 7) // 8, 'big') or b'\0')
        
        
        if verify(msg.encode(), hmacByte,cleint2_symmtric_key)==True:
            print("user2 : ",msg+"     (verified)")
            
        else:
            print("user2 : ",msg+"     (not verified)")
            

def sendToServer():
    a= "start"
    while a!= DISCONNECT_MESSAGE:
        a= input()
        a=a.encode()
        #print(a,type(a),"a")
        #print(k1,type(k1),"k1")
        #encrpys msg with aes and send it to server
        send(encryptAES(a,str(k1).encode()))
        #send msg hmac
        print("sign(a,str(k1).encode()",sign(a,str(k1).encode()))
        send(int.from_bytes(sign(a,str(k1).encode()), "big") )
          
    client.close()
#----------------------------------------------------------------------
# code for HMAC
# xor msg with key and return their hashed value
def sign(msg,key):
    h = blake2b(digest_size=32, key=key)
    h.update(msg)
    return h.hexdigest().encode('utf-8')
# get enterd msg hash value and compare it with enterd hmac
def verify(msg, sig,key):
    good_sig = sign(msg,key)
    return compare_digest(good_sig, sig)
#----------------------------------------------------------------------
# starting the program
    
# serverden enter port msg
print(client.recv(2048).decode(FORMAT))
# entered port number
a= input()
send(a)
# server sended that other cleint entered port number
client.recv(2048).decode(FORMAT)
#print 
print("connection was established")
print("---------user1(your) information--------")
print ("Your public key is ", public ," and your private key is ", private)
# send public key to other cleint 
send(public[0])
# recive public key e part  of other cleint
cleint2_public_e=client.recv(2048).decode(FORMAT)
# send public key to other cleint 
send(public[1])
# recive public key n part to other cleint
cleint2_public_n=client.recv(2048).decode(FORMAT)

#merge cleint recived public kwey 
cleint2_public=(int(cleint2_public_e),int(cleint2_public_n))

# generate nounce and send it to user2 to verify user public key 
# we send nonce without encryption just for authuntication and preventing replay attack
nounce= random.randrange(2**70, 2**71)
# encryption with private key (dijital signatur)

encryptedNounce =encrypt(private, str(nounce))
print ("Your nounce is: ",nounce)
#print ("Your enc nounce is: ",encryptedNounce)
print("---------user2 information--------")
print("user 2 public key :("+cleint2_public_e+" , "+cleint2_public_n+")")

send( nounce)
# recive other cleint nounce
cleint2_nonce=str(client.recv(2048).decode(FORMAT))
print ("user2 nounce",cleint2_nonce)
# send encrydted nounce to other side
time.sleep(3)
send( encryptedNounce)
print(  "nounce", nounce,type(nounce))
print("encryptedNounce",encryptedNounce,type(encryptedNounce))
# recive other cleint nounce
cleint2_encrypted_nonce=str(client.recv(2048).decode(FORMAT))

#resived encrypted msg


cleint2_decrypted_nonce=decrypt( cleint2_public, cleint2_encrypted_nonce)
print(cleint2_decrypted_nonce,type(cleint2_decrypted_nonce))
print("user2  cleint2_encrypted_nonce" ,cleint2_encrypted_nonce,type(cleint2_encrypted_nonce))
if cleint2_decrypted_nonce==cleint2_nonce:
    print("nounce has been verified")
    print("you can send your msg safely")
    #generate  symmetric key

    k1=random.randrange(2**52, 2**53)
    print("user1(My)_symmtric_key",k1)
    enc_k1=encrypt(cleint2_public, str(k1))
    send(enc_k1)
    #print("user1 encrypted  _symmtric_key",enc_k1)

    temp= client.recv(2048).decode(FORMAT)

    
 
    cleint2_symmtric_key=decrypt( private, temp)
    cleint2_symmtric_key= cleint2_symmtric_key.encode()
    
    print("user2_symmtric_key",cleint2_symmtric_key)
    print("---------------------------session has been started----------------------")
# start sending and reciving threads
    listen_thread = threading.Thread(target=listenToServer, args=())
    listen_thread.start()
    send_thread = threading.Thread(target=sendToServer, args=())
    send_thread.start()
else:
    print("nounce has not been verified")
    






