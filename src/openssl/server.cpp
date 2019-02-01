#include <cstring>
#include <arpa/inet.h>
#include <string>
#include <iostream>
#include "ssl_helper.h"


int main(int argc, char *argv[])
{
	//TODO: read the options (port,host,key,cert) using getopts lib
	in_port_t port = 2999;
	in_addr_t addr = INADDR_ANY; //Listen on all interfaces for test purposes
	auto certfile = "./certificate.pem";
	auto keyfile = "./key.pem";

	SSLServer sslServer(addr, port);
	sslServer.Init(certfile, keyfile);
	std::cout << "Server started (Listening on port 2999)." << std::endl;
	sslServer.Start();
}
