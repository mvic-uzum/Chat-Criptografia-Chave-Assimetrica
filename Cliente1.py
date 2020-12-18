# -*- coding: utf-8 -*-
#! /usr/bin/env python

import socket
import pickle
import sys
import time
import threading
import select
import traceback
from cryptography.fernet import Fernet
from hashlib import sha512
import hashlib
import rsa
import os.path

#Código para gerar chaves pública e privada
(pubkey1,privkey1) = rsa.newkeys(1024)
n = pubkey1.n
e = pubkey1.e
d = privkey1.d
np = privkey1.n

SOCKET_LIST = []

class Server(threading.Thread):
    
    def initialise(self, receive):
        self.receive = receive

    def run(self):
        lis = []
        lis.append(self.receive)
        read, write, err = select.select(lis, [], [])
        global pubkey2
        #recebe n
        for item in read: 
            try:
                s = item.recv(1024)
                if s != '':
                    n2 = int(s)
                else:
                    break
            except:
                traceback.print_exc(file=sys.stdout)
                break
        #recebe e
        for item in read: 
            try:
                s = item.recv(1024)
                if s != '':
                    e2 = int(s)
                    pubkey2 = rsa.key.PublicKey(n2,e2)
                else:
                    break
            except:
                traceback.print_exc(file=sys.stdout)
                break
        #recebe o ok do outro cliente para finalizar o handshake
        for item in read:
            try:
                s = item.recv(1024)
                if s != '':
                    ok = s
                    k = open('ok1.txt','wb')
                    k.write(ok)
                    k.close()
                else:
                    break
            except:
                traceback.print_exc(file=sys.stdout)
                break
        #look para recebimento de mensagens
        while 1:
            #recebe a mensagem e descriptografa
            for item in read:
                try:
                    s = item.recv(1024)
                    if s != '':
                        msgcriptografada = s
                        #abrindo a chave simétrica através de um arquivo
                        simk = open('keysimetrica.key','rb')
                        keysimetrica = simk.read()
                        f = Fernet(keysimetrica)
                        msg = f.decrypt(msgcriptografada).decode()    
                    else:
                        break
                except:
                    traceback.print_exc(file=sys.stdout)
                    break
            #recebe a assinatura, confere e printa a mensagem descriptografada na tela
            for item in read:
                try:
                    s = item.recv(1024)
                    if s != '':
                        assi2 = s
                        msgh = msg.encode()
                        hashnovo = int.from_bytes(hashlib.sha1(msgh).digest(), byteorder='big')
                        assi2novo = pow(int(assi2),e2,n2)
                        if(hashnovo == assi2novo):
                            print(msg + '\n:')
                        else:
                            print('A mensagem não foi recebida de forma íntegra!')
                            exit()
                except:
                    traceback.print_exc(file=sys.stdout)
                    break


class Client(threading.Thread):

    def connect(self, host, port):
        self.sock.connect((host, port))

    def client(self, host, port, msg):
        sent = self.sock.send(msg)
        # print "Sent\n"

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            host = input("Enter the server IP:\n")
            port = int(input("Enter the server Destination Port:\n"))
        except EOFError:
            print("Error")
            return 1
        print("Connecting\n")
        s = ''
        self.connect(host, port)
        print("Connected\n")
        user_name = input("Enter the User Name to be Used:\n")
        time.sleep(1)
        srv = Server()
        srv.initialise(self.sock)
        srv.daemon = True
        print("Starting service")
        srv.start()
        SOCKET_LIST.append(self.sock)
        #envia n da chave pública 1
        self.client(host,port,bytes(str(n), encoding='utf8'))
        time.sleep(1)
        #envia e da chave pública 1 e aguarda pela chave pública 2
        self.client(host,port,bytes(str(e), encoding='utf8'))
        time.sleep(3)
        #cria chave simétrica e a envia criptografada
        keysimetrica = Fernet.generate_key()
        f = Fernet(keysimetrica)
        sk = open('keysimetrica.key','wb') #salva em um arquivo
        sk.write(keysimetrica)                                                                                                      
        sk.close()
        simkeycripto = rsa.encrypt(keysimetrica,pubkey2)
        self.client(host,port,simkeycripto)
        time.sleep(4)
        #cria o hash e a assinatura da chave e o envia
        hash1 = rsa.compute_hash(keysimetrica, 'SHA-1') 
        assinatura = rsa.sign_hash(hash1, privkey1, 'SHA-1')
        self.client(host,port,assinatura)
        time.sleep(5)
        while 1: #checa se já acabou o handshake
            if (os.path.isfile('ok1.txt')): 
                if (os.path.getsize('ok1.txt') > 0):
                    break
                else:
                    print("Aguardando Fim do Handshake...")
                    time.sleep(10)
            else:
                print("Aguardando Fim do Handshake...")
                time.sleep(10)
        while 1:
            msg = input(':')
            if(len(msg)>256): #verificando se a mensagem possui mais de 255 caracteres
                print("Não é permitido enviar mensagem com mais de 255 caracteres!")
                break
            if msg == 'exit':
                break
            if msg == '':
                continue
            #para enviar mensagem
            msg = user_name + ":" + msg
            msgh = msg.encode()
            msgcriptografada = f.encrypt(msg.encode())
            self.client(host, port, msgcriptografada)
            time.sleep(2)
            hash2= int.from_bytes(hashlib.sha1(msgh).digest(), byteorder='big') #hash e assinatura da mensagem
            assinatura2 = pow(hash2,d,np)
            self.client(host,port,bytes(str(assinatura2), encoding='utf8'))
            time.sleep(5)
        return (1)

if __name__ == '__main__':
    print("Starting client")
    cli = Client()
    cli.start()