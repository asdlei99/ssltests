/**
   ssltests
   SSLClient.h
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

#ifndef _SSLClient_h
#define _SSLClient_h

#include <iostream>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CLIENT_CERTFILE "../certs/thawte_cert.cer"

using namespace std;

class SSLClient {
private:
	string host;
	int port;
	bool clientRunning;

	const SSL_METHOD* sslMethod;
	SSL_CTX* clientCTX;
	BIO* clientBIO;
	SSL* ssl; // SSL structure

private:
	bool initSSL();
    
public:
    SSLClient();
    ~SSLClient();
    
	bool initSocket(string, int);
    bool attemptConnect();
	void readData();
	void writeData(char*, unsigned int);
	void disconnect();

	void setClientRunning(bool c) {
		clientRunning = c;
	}

	bool isClientRunning() {
		return clientRunning;
	}

};

#endif
