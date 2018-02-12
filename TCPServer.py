from socket import *
from urllib.parse import urlparse
import _thread
import hashlib
import sys
import requests

serverAddress = 'localhost'
virusUrl = "https://www.virustotal.com/vtapi/v2/file/scan"
apiKey = "7df792b5fbc76612624c86b8ca4feb70d63a188ae2740bbdfd044f4e071b865a"
html = """<html>
    <body>
        <h1>Hello</h1>
        You have found a virus!
    </body>
</html>"""

def start_thread(connectedSocket,apiNumber):
    decoded = ""
    print("Receiving from:", connectedSocket.getpeername())
    getMSG = True

    while getMSG: # retrieve data from from the client
        sentence = connectedSocket.recv(2048).decode('unicode_escape')
        decoded = decoded + sentence
        if decoded.endswith('\r\n\r\n') or sentence == '\r\n':
            getMSG = False
    print("Received the message from:", connectedSocket.getpeername())

    if "Connection: keep-alive" in decoded:
        decoded = decoded.replace("Connection: keep-alive", "Connection: close")

    parsed = decoded.strip().split(" ")  # Splitting request into three parts with white space as divider
    requestPort = 80  # Default Port
    URL = parsed[1]
    parsedURL = urlparse(URL)
    if parsedURL.port is not None:
        requestPort = parsedURL.port

    requestSocket = socket(AF_INET, SOCK_STREAM)
    requestURL = parsedURL.netloc.replace("www.", "")
    if str(requestPort) in requestURL:
        requestURL = requestURL.replace(str(requestPort), '')
        requestURL = requestURL.replace(':', '')
    
    if "User-Agent: Mozilla/5.0" in decoded:
        requestSocket.connect((requestURL, requestPort))
        requestSocket.send(decoded.encode())
        sentence = requestSocket.recv(2048)
        virusMessage = sentence
        connectedSocket.send(sentence)
        while len(sentence) != 0:
            print("Receiving Mozilla")
            sentence = requestSocket.recv(2048)
            connectedSocket.send(sentence)
            print("Sending Mozilla")
        # close both sockets
        requestSocket.close()
        connectedSocket.close()

    elif "User-Agent: Wget" in decoded:
        userAgent = "Wget"
        requestSocket.connect((requestURL, requestPort)) # connected to the server and pass along the message
        requestSocket.send(decoded.encode())
        sentence = requestSocket.recv(2048)
        virusMessage = sentence
        while len(sentence) != 0:
            print("Receiving Wget")
            sentence = requestSocket.recv(2048)
            virusMessage = virusMessage + sentence
        # split the headers from the body so the proxy can send just the body
        headers, vMessage = virusMessage.decode('unicode_escape').split('\r\n\r\n')
        if checkSum(vMessage, userAgent, apiNumber) is True:
            connectedSocket.send(headers.encode())
            # if a virus is found return a html saying there is a virus
            connectedSocket.send(html.encode())
        else:
            connectedSocket.send(virusMessage)
        # close both sockets
        requestSocket.close()
        connectedSocket.close()
        
    elif "User-Agent: curl" in decoded:
        userAgent = "curl"
        # connected to the server and pass along the message
        requestSocket.connect((requestURL, requestPort))
        requestSocket.send(decoded.encode())
        sentence = requestSocket.recv(2048)
        virusMessage = sentence
        while len(sentence) != 0:
            print("Receiving curl")
            sentence = requestSocket.recv(2048)
            virusMessage = virusMessage + sentence
        # split the headers from the body so the proxy can send just the body
        headers, vMessage = virusMessage.decode('unicode_escape').split('\r\n\r\n')

        if checkSum(vMessage, userAgent,apiNumber) is True:
            connectedSocket.send(headers.encode())
            # if a virus is found return a html saying there is a virus
            connectedSocket.send(html.encode())
        else:
            connectedSocket.send(virusMessage)
        #close both sockets
        requestSocket.close()
        connectedSocket.close()
    else:
        userAgent = "gzip"
        method = parsed[0]
        version = parsed[2]
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

        requestSocket.connect((requestURL, requestPort))
        requestMg = "GET " + parsedURL.path + " HTTP/1.0\n" + "Host: " + parsedURL.netloc + "\n" + "Connection: close\n\r\n"
        print("Sending message to: " + requestURL + " at port: " + str(requestPort))
        print(requestMg)
        requestSocket.send(requestMg.encode())
        sentence = requestSocket.recv(2048)
        virusMessage = sentence
        while len(sentence) != 0:
            connectedSocket.send(sentence)
            sentence = requestSocket.recv(2048)
            virusMessage = virusMessage + sentence

        headers, vMessage = virusMessage.decode('unicode_escape').split('\r\n\r\n')

        if checkSum(vMessage, userAgent,apiNumber) is True:
            connectedSocket.send(headers.encode())
            # if a virus is found return a html saying there is a virus
            connectedSocket.send(html.encode())
        else:
            connectedSocket.send(virusMessage)
        # close both sockets
        requestSocket.close()
        connectedSocket.close()
    

def checkSum(message, agent,apiNumber):
    # creates a reference number for virustotal
    hash_md5 = hashlib.md5(message.encode())
    params = {'apikey': apiNumber, 'resource': hash_md5}
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": agent
    }
    # using the python response library
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                            params=params, headers=headers)
    json_response = response.json()
    # if the value associated with positives is anything other than 0 there are viruses
    if json_response.get("positives") != 0:
        return True
    else:
        return False

def main():
    if len(sys.argv) < 2:
        print("Did not give enough parameters")
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
        _thread.start_new_thread(start_thread, (connectionSocket, apiNumber))


if __name__ == "__main__":
    main()

