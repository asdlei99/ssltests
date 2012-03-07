/**
   ssltests
   SSLServer.h
   Copyright 2011 Ramsey Kant

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#ifndef _sslserver_h_
#define _sslserver_h_

#include <iostream>
#include <list>

#include <boost/thread.hpp>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "Connection.h"

#define SERVER_PORT 443
#define SERVER_CERTPWD "1234"
#define SERVER_CERTFILE "../certs/s_ssl.crt"
#define SERVER_PVKFILE "../certs/s_ssl.pvk"

using namespace std;

class SSLServer {
private:
	BIO* listenBIO;
	const SSL_METHOD* sslMethod;
	SSL_CTX* serverCTX;

	list<Connection*> *cons;

private:
	void acceptConnection();

	static int passwordCallback(char *buf, int size, int rwflag, void *password) {
		strncpy(buf, (char *)(SERVER_CERTPWD), size);
		buf[size - 1] = '\0';
		return(strlen(buf));
	}

public:
	SSLServer();
	~SSLServer();
	bool init();
	void run();
	void disconnectAll();
};

#endif