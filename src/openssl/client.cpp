#include <cstdio>
#include <cstring>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <iostream>
#include <arpa/inet.h>
#include "ssl_helper.h"

int main(int argc, char *argv[])
{
	if (argc < 3){
		std::cout << "Usage: " << argv[0] << " IP PORT" << std::endl;
		exit(-1);
	}
	auto host= argv[1]; //TODO: use getopt to read address and port from cli
	in_addr_t addr;
	in_port_t port = atoi(argv[2]);
	inet_pton(AF_INET, host, &addr);

	SSLClient sslClient(addr, port);
	sslClient.Init();
	sslClient.Connect();
	sslClient.Send("HELLO");
	auto response  = sslClient.Receive();
	std::cout << response;
	sslClient.Disconnect();

	return 0;
}