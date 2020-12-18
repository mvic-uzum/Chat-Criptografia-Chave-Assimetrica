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
(pubkey2,privkey2) = rsa.newkeys(1024)
n = pubkey2.n
e = pubkey2.e
d = privkey2.d
np = privkey2.n

class Server(threading.Thread):
    
    def initialise(self, receive):
        self.receive = receive

    def run(self):
        lis = []
        lis.append(self.receive)
        read, write, err = select.select(lis, [], [])
        #recebe n
        for item in read: 
            try:
                s = item.recv(1024)
                if s != '':
                    n1 = int(s)
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
                    e1 = int(s)
                    pubkey1 = rsa.key.PublicKey(n1,e1)
                else:
                    break
            except:
                traceback.print_exc(file=sys.stdout)
                break
        #recebe chave simétrica
        for item in read:
            try:
                s = item.recv(1024)
                if s != '':
                    keysimetricacriptografada = s
                    keysimetrica = rsa.decrypt(keysimetricacriptografada,privkey2)
                else:
                    break
            except:
                traceback.print_exc(file=sys.stdout)
                break
        #recebe e confere a assinatura da chave simétrica
        for item in read:
            try:
                s = item.recv(1024)
                if s != '':
                    assi = s
                    if (rsa.verify(keysimetrica, assi, pubkey1)):
                        print('A chave simétrica foi recebida de forma íntegra (:')
                        sk = open('keysimetrica2.key','wb') #salva em um arquivo
                        sk.write(keysimetrica)                                                                                                      
                        sk.close()
                        f = Fernet(keysimetrica)
                        #envia um ok para finalizar o handshake
                        ok = "ok" 
                        self.receive.send(bytes(ok, encoding='utf8'))
                    else:
                        print('A chave simétrica não foi recebida de forma íntegra!')
                        exit()
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
                        assi2novo = pow(int(assi2),e1,n1)
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
        #envia n da chave pública 2
        self.client(host,port,bytes(str(n), encoding='utf8'))
        time.sleep(1)
        #envia e da chave pública 2 e aguarda pela chave pública 2
        self.client(host,port,bytes(str(e), encoding='utf8'))
        time.sleep(5)
        while 1: #checa se já recebeu a chave simétrica
            if (os.path.isfile('keysimetrica2.key')): 
                if (os.path.getsize('keysimetrica2.key') > 0):
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
            #pega a chave simétrica de um arquivo
            simk = open('keysimetrica2.key','rb')
            keysimetrica = simk.read()
            f = Fernet(keysimetrica)
            msgcriptografada = f.encrypt(msg.encode())
            self.client(host, port, msgcriptografada)
            time.sleep(2)
            hash1 = int.from_bytes(hashlib.sha1(msgh).digest(), byteorder='big') #hash e assinatura da mensagem
            assinatura1 = pow(hash1,d,np)
            self.client(host,port,bytes(str(assinatura1), encoding='utf8'))
            time.sleep(5)
        return (1)

if __name__ == '__main__':
    print("Starting client")
    cli = Client()
    cli.start()