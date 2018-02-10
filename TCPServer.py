from socket import *
from urllib.parse import urlparse
import _thread
import hashlib
import sys
import requests

serverAddress = 'localhost'
apiNumber = 0
virusUrl = "https://www.virustotal.com/vtapi/v2/file/scan"
myAPIKey = "7df792b5fbc76612624c86b8ca4feb70d63a188ae2740bbdfd044f4e071b865a"
userAgent = ""


def start_thread(connectedSocket):
    decoded = ""
    print("Receiving from:", connectedSocket.getpeername())
    getMSG = True
    while getMSG:
        sentence = connectedSocket.recv(2048).decode('unicode_escape')
        decoded = decoded + sentence
        if decoded.endswith('\r\n\r\n') or sentence == '\r\n':
            getMSG = False
    print("Received the message from:",connectedSocket.getpeername())

    if "Connection: keep-alive" in decoded:
        decoded = decoded.replace("Connection: keep-alive", "Connection: close")

    parsed = decoded.strip().split(" ")  # Splitting request into three parts with white space as divider
    requestPort = 80  # Default Port

    URL = parsed[1]
    parsedURL = urlparse(URL)

    if parsedURL.port is not None:
        requestPort = parsedURL.port

    if "User-Agent: Mozilla/5.0" in decoded:
        requestSocket = socket(AF_INET, SOCK_STREAM)
        requestURL = parsedURL.netloc.replace("www.", "")
        print("mozilla URL", URL)
        print("mozilla requestURL", requestURL)
        requestSocket.connect((requestURL, requestPort))
        requestSocket.send(decoded.encode())
        print("mozilla Sent to requestSocket")
        sentence = requestSocket.recv(2048)
        connectedSocket.send(sentence)
        while len(sentence) != 0:
            print("Receiving Mozilla")
            sentence = requestSocket.recv(2048)
            connectedSocket.send(sentence)
            print("Sending Mozilla")

        requestSocket.close()
        connectedSocket.close()

    elif "User-Agent: curl" in decoded:
        userAgent = "curl"
        requestSocket = socket(AF_INET, SOCK_STREAM)
        requestURL = parsedURL.netloc.replace("www.", "")
        print("curl URL", URL)
        print("curl requestURL", requestURL)
        requestSocket.connect((requestURL, requestPort))
        requestSocket.send(decoded.encode())
        print("curl Sent to requestSocket")
        sentence = requestSocket.recv(2048)
        virusMessage = sentence
        print("curl Receiving from request")
        while len(sentence) != 0:
            print("Receiving Curl")
            sentence = requestSocket.recv(2048)
            virusMessage = virusMessage + sentence
        checkSum(virusMessage, userAgent)
        connectedSocket.send(virusMessage)
        requestSocket.close()
        connectedSocket.close()

    elif "User-Agent: Wget" in decoded:
        userAgent = "Wget"
        requestSocket = socket(AF_INET, SOCK_STREAM)
        requestURL = parsedURL.netloc.replace("www.", "")
        print("wget URL", URL)
        print("wget requestURL", requestURL)
        requestSocket.connect((requestURL, requestPort))
        requestSocket.send(decoded.encode())
        print("wget Sent to requestSocket")
        sentence = requestSocket.recv(2048)
        virusMessage = sentence
        print("wget Receiving from request")
        while len(sentence) != 0:
            print("Receiving Wget")
            sentence = requestSocket.recv(2048)
            virusMessage = virusMessage + sentence

        checkSum(virusMessage, userAgent)

        connectedSocket.send(virusMessage)
        requestSocket.close()
        connectedSocket.close()
    else:
        method = parsed[0]
        version = parsed[2]
        print(len(parsed))
        if len(parsed) != 3:
            response = "ERROR 400: BAD REQUEST"
            connectedSocket.send(response.encode())
            connectedSocket.close()
            return

        if method != 'GET':
            response = "ERROR 501: NOT IMPLEMENTED"
            connectedSocket.send(response.encode())
            connectedSocket.close()
            return

        if version != 'HTTP/1.0':
            response = "ERROR: DID NOT RECEIVE A SUPPORTED VERSION"
            connectedSocket.send(response.encode())
            connectedSocket.close()
            return



        if parsedURL.port is not None:
            requestPort = parsedURL.port

        requestSocket = socket(AF_INET, SOCK_STREAM)
        requestURL = parsedURL.netloc.replace("www.", "")

        requestSocket.connect((requestURL, requestPort))
        requestMg = "GET " + parsedURL.path + " HTTP/1.0\n" + "Host: " + parsedURL.netloc + "\n" + "Connection: close\n\r\n"
        print("Sending message to: " + requestURL + " at port: " + str(requestPort))
        print(requestMg)
        requestSocket.send(requestMg.encode())
        sentence = requestSocket.recv(2048)

        while len(sentence) != 0:
            connectedSocket.send(sentence)
            sentence = requestSocket.recv(2048)

        connectedSocket.send(sentence)
        requestSocket.close()
        connectedSocket.close()
    #connectedSocket.close()

    '''
    1
    Received request:  GET http://detectportal.firefox.com/success.txt HTTP/1.0
    Host: detectportal.firefox.com
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0
    Accept: */*
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Cache-Control: no-cache
    Pragma: no-cache
    Connection: keep-alive

    '''
def checkSum(message, agent):

    hash_md5 = hashlib.md5(message)
    params = {'apikey': myAPIKey, 'resource': '7657fcb7d772448a6d8504e4b20168b8'}
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": agent
    }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                            params=params, headers=headers)
    json_response = response.json()
    print(json_response)

def main():
    if len(sys.argv) < 2:
        print("Did not give enought parameters")
        return
    if sys.argv[1] is None or sys.argv[2] is None:
        print("You inputs were off, what server port did you want to use?")
        serverPort = int(input())
        print("What API number? or NA if not")
        apiNumber = int(input())
    else:
        serverPort = int(sys.argv[1])
        apiNumber = int(sys.argv[2])
    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    serverSocket.bind(('', serverPort))
    serverSocket.listen(1)
    print('Server ready to receive...')
    while 1:
        connectionSocket, addr = serverSocket.accept()
        print("Received connection from: ", connectionSocket.getpeername())
        _thread.start_new_thread(start_thread, (connectionSocket,))


if __name__ == "__main__":
    main()

