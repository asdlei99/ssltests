/**
   ssltests
   SSLServer.cpp
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

#include "SSLServer.h"

SSLServer::SSLServer() {
	// SSL variables
	sslMethod = NULL;
	listenBIO = NULL;
	serverCTX = NULL;

	cons = new list<Connection*>();
}

SSLServer::~SSLServer() {
	disconnectAll();
	if(serverCTX)
		SSL_CTX_free(serverCTX);
	if(listenBIO)
		BIO_free(listenBIO);

	delete cons;
}

bool SSLServer::init() {
	// Create a CTX structure with a method indicating that we only understand TLSv1
	sslMethod = TLSv1_server_method();
	serverCTX = SSL_CTX_new(sslMethod);
	if(!serverCTX) {
		printf("Could not create serverCTX\n");
		return false;
	}

	// Set default password for key files
	SSL_CTX_set_default_passwd_cb(serverCTX, passwordCallback);

	// Load the server certificate into the serverCTX
	if(SSL_CTX_use_certificate_file(serverCTX, SERVER_CERTFILE, SSL_FILETYPE_PEM) <= 0) {
		printf("Couldn't load certificate file\n");
		return false;
	}

	// Load the corresponding private key into the serverCTX
	if(SSL_CTX_use_PrivateKey_file(serverCTX, SERVER_PVKFILE, SSL_FILETYPE_PEM) <= 0) {
		printf("Could not load private key file\n");
		return false;
	}

	// Make sure private key and certificate correspond
	if(!SSL_CTX_check_private_key(serverCTX)) {
		printf("Private Key and Certificate do NOT match\n");
		return false;
	}

	// Proxy will not verify the client (request for the client's certificate won't be sent)
	SSL_CTX_set_verify(serverCTX, SSL_VERIFY_NONE, NULL);

	// Enable all cipher suites
	if(SSL_CTX_set_cipher_list(serverCTX, "ALL") <= 0) {
		printf("Could not select any ciphers\n");
		return false;
	}

	// Setup the accepting BIO
	listenBIO = BIO_new(BIO_s_accept());
	if(!listenBIO) {
		printf("Couldn't setup accepting BIO\n");
		return false;
	}

	// Setup the accepting BIO
	char port[8];
	sprintf(port, "%i", SERVER_PORT);
	listenBIO = BIO_new_accept(port);
	if(!listenBIO) {
		printf("Could not setup accepting BIO\n");
		return false;
	}

	// Set BIO as non blocking (this will make client BIO's that are accepted as non blocking)
	BIO_set_nbio(listenBIO, 1);

	// Bind
	if(BIO_do_accept(listenBIO) <= 0) {
		printf("Could not Bind. Is another program listening on the same port?\n");
		return false;
	}

	printf("SSLServer ready on port %i\n", SERVER_PORT);

	return true;
}

/*
 * Run
 * Accept's new connections (if any)
 */
void SSLServer::run() {
	if(BIO_do_accept(listenBIO) > 0)
		acceptConnection();
}

/**
 * Accept Connection
 * Initialize the SSL context for the client and set it into an accepting state. Spawns the new Connection thread and add's it to the cons list
 */
void SSLServer::acceptConnection() {
	BIO* cbio = BIO_pop(listenBIO);
	SSL* nssl = SSL_new(serverCTX);
	if(!nssl) {
		printf("Couldn't spawn SSL context for new client\n");
		BIO_free(cbio);
		return;
	}

	// Put into accept state then Link BIO to SSL
	SSL_set_accept_state(nssl);
	SSL_set_bio(nssl, cbio, cbio);

	// Create the connection object and spawn it's thread with start()
	Connection* con = new Connection(cbio, nssl);
	cons->push_back(con);
	con->start();

	printf("New client connected\n");
}

/**
 * Disconnect All
 * Notify's all running Connection threads to stop. Once stopped, Connection objects are deleted and the map is cleared
 */
void SSLServer::disconnectAll() {
	// Stop all threads and wait for them to finish their current cycle, then delete the object
    list<Connection*>::const_iterator it;
    for (it = cons->begin(); it != cons->end(); it++) {
        Connection *con = *it;
		con->stop();
		delete con;
    }

	// Remove all connections from the list
	cons->clear();
}
