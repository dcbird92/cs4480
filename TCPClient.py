from socket import *

serverName = 'localhost'
serverPort = 12000
clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverName,serverPort))
sentence = input('Enter MSG: ')
clientSocket.send(sentence.encode())
modifiedSentence = clientSocket.recv(1024)
while len(modifiedSentence) != 0:
    print(modifiedSentence)
    modifiedSentence = clientSocket.recv(1024)
# print('From Server: ', modifiedSentence.decode())
sentence = input('Enter to finish')
clientSocket.close()