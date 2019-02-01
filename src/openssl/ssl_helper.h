#ifndef CPP_CHALLENGE_SSH_HELPER_H
#define CPP_CHALLENGE_SSH_HELPER_H

#include <string>
#include <openssl/ssl.h>

#define MAX_CONNECTIONS 10

class SSLServer {

public:
	SSLServer(in_addr_t address, in_port_t portNum);
	virtual ~SSLServer();

	void Init(std::string certfile, std::string keyfile);
	void Start();

private:
	int sock;
	SSL_CTX *sslContext;
	sockaddr_in serviceAddress;
	in_port_t servicePort;

	int openSocket();
	void loadCertificates(std::string CertFile, std::string KeyFile);
	void service(SSL *pSt);
	SSL_CTX *initSSLContext();

	std::string generateResponse(std::string command);
};

class SSLClient {

public:
	SSLClient(in_addr_t address, in_port_t portNum);
	virtual ~SSLClient();

	void Connect();
	void Init();
	int Send(std::string message);
	std::string Receive();
	void Disconnect() const;


private:
	int sock;
	SSL *sslSession;
	SSL_CTX *sslContext;
	sockaddr_in serviceAddress;

	int openSocket();
	SSL_CTX *initSSLContext();

};
#endif //CPP_CHALLENGE_SSH_HELPER_H
