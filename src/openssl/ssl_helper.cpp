#include <unistd.h>
#include <malloc.h>
#include <cstring>
#include <arpa/inet.h>
#include <iostream>
#include <z3.h>
#include <array>
#include <memory>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "ssl_helper.h"

std::string Execute(const char* cmd) {
	//TODO: refactor me into my own class
	std::array<char, 128> buffer;
	std::string result;
	std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
	if (!pipe) {
		throw std::runtime_error("popen() failed!");
	}
	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
		result += buffer.data();
	}
	return result;
}

SSLServer::SSLServer(in_addr_t address, in_port_t portNum) {
	this->serviceAddress.sin_family = AF_INET;
	this->serviceAddress.sin_port = htons(portNum);
	this->serviceAddress.sin_addr.s_addr = address;
}

SSLServer::~SSLServer() {
	close(this->sock);
	SSL_CTX_free(this->sslContext);
}

void SSLServer::Init(std::string certfile, std::string keyfile) {
	SSL_library_init();
	this->sslContext = initSSLContext();
	this->loadCertificates(certfile, keyfile);
}

void SSLServer::Start() {
	openSocket();
	while (true) {
		socklen_t len = sizeof(serviceAddress);

		int client = accept(this->sock, (struct sockaddr *) &serviceAddress, &len);  /* accept connection as usual */
		printf("Connection: %s:%d\n", inet_ntoa(serviceAddress.sin_addr), ntohs(serviceAddress.sin_port));
		SSL *ssl = SSL_new(this->sslContext);
		SSL_set_fd(ssl, client);
		this->service(ssl);
	}
}

void SSLServer::loadCertificates(std::string CertFile, std::string KeyFile) {
	if (SSL_CTX_use_certificate_file(this->sslContext, CertFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		abort();
	}
	if (SSL_CTX_use_PrivateKey_file(this->sslContext, KeyFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* Verify the private key */
	if (!SSL_CTX_check_private_key(this->sslContext)) {
		std::cerr << "Private key does not match the public certificate" << std::endl;
		abort();
	}
}

void SSLServer::service(SSL *ssl) {
	char buf[1024];
	char reply[1024];
	int sd, bytes;
	const char *echo = "%s\n\n";

	if (SSL_accept(ssl) < 0)
		ERR_print_errors_fp(stderr);
	else {
		bytes = SSL_read(ssl, buf, sizeof(buf));
		if (bytes > 0) {
			buf[bytes] = 0;
			printf("Received: \"%s\"\n", buf);
			std::string response = this->generateResponse(std::string(buf));
			SSL_write(ssl, response.c_str(), response.length());
		} else
			ERR_print_errors_fp(stderr);
	}
	sd = SSL_get_fd(ssl);
	SSL_free(ssl);
	close(sd);
}

int SSLServer::openSocket() {
	this->sock = socket(PF_INET, SOCK_STREAM, 0);
	if (bind(sock, (struct sockaddr *) &serviceAddress, sizeof(serviceAddress)) != 0) {
		perror("can't bind port");
		abort();
	}
	if (listen(sock, MAX_CONNECTIONS) != 0) {
		perror("Can't configure listening port");
		abort();
	}
	return sock;
}

SSL_CTX *SSLServer::initSSLContext() {
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	const SSL_METHOD *method = TLSv1_2_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (ctx == nullptr) {
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

std::string SSLServer::generateResponse(std::string command) {
	if (command == "HELLO"){
		//TODO: call a shell script instead of ls :)
		return Execute("ls");
	} else {
		return "Unknown Command";
	}
}

SSL_CTX *SSLClient::initSSLContext() {
	SSL_METHOD *method;
	SSL_CTX *ctx;

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	method = const_cast<SSL_METHOD *>(TLSv1_2_client_method());
	ctx = SSL_CTX_new(method);
	if ( ctx == nullptr)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

SSLClient::~SSLClient() {
	close(this->sock);
	if (this->sslContext)
		SSL_CTX_free(this->sslContext);
}

SSLClient::SSLClient(in_addr_t address, in_port_t portNum) {
	this->serviceAddress.sin_family = AF_INET;
	this->serviceAddress.sin_port = htons(portNum);
	this->serviceAddress.sin_addr.s_addr = address;
}

int SSLClient::openSocket() {
	this->sock = socket(PF_INET, SOCK_STREAM, 0);

	if (connect(this->sock, (struct sockaddr *) &this->serviceAddress, sizeof(this->serviceAddress)) != 0) {
		close(this->sock);
		perror("Connection failure");
		abort();
	}
	return this->sock;
}

void SSLClient::Init() {
	SSL_library_init();
	this->sslContext = initSSLContext();
}

void SSLClient::Connect() {
	this->sock = openSocket();
	this->sslSession = SSL_new(this->sslContext);
	if (SSL_set_fd(this->sslSession, this->sock) == 0){
		abort();
	}
	if (SSL_connect(this->sslSession) != 1)
		ERR_print_errors_fp(stderr);//FIXME: throw
	std::cout << "Connected with encryption: "
	          << std::string(SSL_get_cipher(this->sslSession)) << std::endl;
}

int SSLClient::Send(std::string message) {
	return SSL_write(this->sslSession, message.c_str(), message.length());
}

void SSLClient::Disconnect() const {
	SSL_free(this->sslSession);
}

std::string SSLClient::Receive() {
	char buf[1024] = {0};
	int bytes = SSL_read(this->sslSession, buf, sizeof(buf));
	buf[bytes] = 0;
	return std::string(buf);
}
