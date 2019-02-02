# Writeup
To build the cpp projects (including openssl):

    mkdir build && cd build && cmake ../ && make

cmake 3.5.1 and gcc 5.4.0 have been used.

# Pthread
To test the project:

    src/cpp/threads

 Sample output:

    Please enter the number of threads to create: 5
    Thread with id : 139820223272704 started
    Thread with id : 139820198094592 started
    Thread with id : 139820214880000 started
    Thread with id : 139820206487296 started
    Thread with id : 139820063876864 started
    Thread with id : 139820223272704 is exiting
    Thread with Id : 139820223272704 exited and returned : 3
    Thread with id : 139820063876864 is exiting
    Thread with id : 139820206487296 is exiting
    Thread with id : 139820198094592 is exiting
    Thread with id : 139820214880000 is exiting
    Thread with Id : 139820214880000 exited and returned : 7
    Thread with Id : 139820206487296 exited and returned : 5
    Thread with Id : 139820063876864 exited and returned : 3
    Thread with Id : 139820198094592 exited and returned : 6


# Openssl
## Question 1

To build the proejct:

To test server:

    openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout key.pem -out certificate.pem
    sudo ./srever 

Sample output:

    Server started (Listening on port 2999).
    Received: "HELLO"
    Connection: 127.0.0.1:47038


To test client:
./client 127.0.0.1 2999

which will output: `Connected with encryption: AES256-GCM-SHA384` followed by the output from server’s execute shell command, in this case `ls` command.

Sample output:

    certificate.pem
    client
    CMakeCache.txt
    CMakeFiles
    key.pem
    server

Note: the client does not check for the authenticity of the server's certificate.

# Python
## Question 1

The first question is coded in `Intercepter.py` which connect two endpoints from port `3111` to `2999` as requested.
To test:
Since I didn’t implement the insecure server client program, we can use other servers instead.

    sudo socat tcp-listen:2999,fork,reuseaddr TCP4:towel.blinkenlights.nl:21

which willl listen on port `2999` as our server.

Then run interceptor to sniff the communications:

    sudo python3.5 ../src/python/Intercepter.py

Then connect to the server through the interceptor:

    socat - tcp-connect:localhost:3111


## Question 2

This one is in `Sniffer.py` and it ask the user for the interface name to sniff.

    sudo python3.5 ../src/python/Sniffer.py
    Please enter interface name: 

Sample output:

    Destination MAC : DD:EE:FF:AA:BB:CC: Source MAC : AA:BB:CC:DD:EE:FF Protocol : 8
    Source Address : 192.168.0.1  Destination Address : 192.168.0.101 Version : 4 IP Header Length : 5 
    Source Port : 1080 Dest Port : 37298  Sequence Number : 4066805133 Acknowledgement : 124644096 TCP header length : 8 
    
    Destination MAC : AA:BB:CC:DD:EE:FF Source MAC : DD:EE:FF:AA:BB:CC: Protocol : 8
    Source Address : 192.168.0.101  Destination Address : 192.168.0.1 Version : 4 IP Header Length : 5 
    Source Port : 37298 Dest Port : 1080  Sequence Number : 124644096 Acknowledgement : 4066805236 TCP header length : 8 
    ...

