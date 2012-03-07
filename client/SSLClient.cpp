/**
   ssltests
   SSLClient.cpp
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

#include "SSLClient.h"

/**
 * Client Constructor
 * Initializes default values for private members
 *
 */
SSLClient::SSLClient() {
	host = "";
	port = 443;
	clientRunning = false;
	clientBIO = NULL;
	ssl = NULL;
}

/**
 * Client Destructor
 */
SSLClient::~SSLClient() {
	if(ssl)
		disconnect();
}

/**
 * InitSocket
 * Initialize the socket and put it in a state thats ready to connect
 *
 * @param host Server host string
 * @param port Server port to connect to (default is 443)
 * @return True on success, false otherwise
 */
bool SSLClient::initSocket(string h, int p) {
    // Setup the address structure
	host = h;
	port = p;
	char constr[32];
	sprintf(constr, "%s:%i", h.c_str(), port);

	// Attempt to init SSL
	if(!initSSL()) {
		printf("SSLClient: Had a problem initializing SSL\n");
		return false;
	}

    // Setup connection
	clientBIO = BIO_new_connect(constr);
	if(!clientBIO) {
		printf("SSLClient: Error creating clientBIO\n");
		return false;
	}

	// Set BIO as non blocking
	BIO_set_nbio(clientBIO, 1);

	return true;
}

/**
 * Init SSL
 * Initialize the SSL Method and client context as well as load the appropriate certificates and cipher suites
 *
 * @return True if successful, false if otherwise
 */
bool SSLClient::initSSL() {
	// Create a CTX structure with a method indicating that we only understand TLSv1
	sslMethod = TLSv1_client_method();
	clientCTX = SSL_CTX_new(sslMethod);
	if(!clientCTX) {
		printf("SSLClient: Could not create clientCTX\n");
		return false;
	}

	// Load the trusted certificate into the clientCTX
	if(SSL_CTX_load_verify_locations(clientCTX, CLIENT_CERTFILE, NULL) <= 0) {
		printf("SSLClient: Couldn't load verification cert file\n");
		return false;
	}

	// We won't verify the server against a CA
	SSL_CTX_set_verify(clientCTX, SSL_VERIFY_NONE, NULL);

	// Enable all cipher suites
	if(SSL_CTX_set_cipher_list(clientCTX, "ALL") <= 0) {
		printf("Could not select any ciphers\n");
		return false;
	}

	return true;
}

/**
 * Connect
 * Attempt to connect to the target host. Do NOT call if initSocket() failed
 *
 * @return True if succeeded
 */
bool SSLClient::attemptConnect() {
	// Attempt to connect to the server
	bool con = (BIO_do_connect(clientBIO) > 0) ? true : false;
	printf("SSLClient: Attempting to connect to %s:%i...\n", host.c_str(), port);

	// Because it's a nonblocking BIO, keep retrying the connect until indicated otherwise
	while(!con && BIO_should_retry(clientBIO)) {
		if(BIO_do_connect(clientBIO) > 0) {
			con = true;
			break;
		}
	}
	if(!con) {
		printf("SSLClient: Could not connect to remote host\n");
		SSL_CTX_free(clientCTX);
		return false;
	}

	// Create a new SSL structure for the client based on the context
	ssl = SSL_new(clientCTX);
	if(!ssl) {
		printf("SSLClient: Couldn't create a new SSL structure\n");
		BIO_free(clientBIO);
		SSL_CTX_free(clientCTX);
		return false;
	}

	SSL_set_connect_state(ssl);
	SSL_set_bio(ssl, clientBIO, clientBIO);
	
	// SSL_connect: Perform SSL handshake
	// Non-blocking: Retry the connect call as long as we are allowed to (BIO_should_retry)
	if(SSL_connect(ssl) <= 0) {
		while(BIO_should_retry(clientBIO)) {
			if(SSL_connect(ssl) > 0)
				clientRunning = true;
		}
	} else {
		clientRunning = true;
	}

	// Connect wasn't successful
	if(!clientRunning) {
		printf("SSLClient: SSL_connect failed\n");
		return false;
	}

	printf("SSLClient: Connection was successful!\n");
	return true;
}

/**
 * Read Data
 * Check's if there is any new data to read on the wire
 */
void SSLClient::readData() {
	/*if(!BIO_should_read(clientBIO))
		return;*/

	int r = 0;
	unsigned int bytesRead = 0, maxLen = 4096;
	char *pData = new char[maxLen];

	// Loop and grab all data on the wire
	do {
		bytesRead += r;
		r = SSL_read(ssl, pData+bytesRead, maxLen-bytesRead);
	} while(r > 0);

	// Check to see if the connection was closed
	if((r == 0) || (SSL_get_shutdown(ssl) != 0)) {
		printf("Server closed the connection\n");
		clientRunning = false;
	}
	
	// If data was read, print it out
	if(bytesRead > 0) {
		printf("Received %u bytes from server:\n", bytesRead);
		for(unsigned int i = 0; i < bytesRead; i++) {
			printf("0x%X ", pData[i]);
		}
		printf("\n");
		for(unsigned int i = 0; i < bytesRead; i++) {
			printf("%c", pData[i]);
		}
		printf("\n");
	}

	delete [] pData;
}

void SSLClient::writeData(char* pData, unsigned int len) {
	int r = 0;
	unsigned int totalSent = 0, bytesLeft = len, dataLen = len;

	// Loop until all data is written to the wire
	while(totalSent < dataLen) {
		r = SSL_write(ssl, pData+totalSent, bytesLeft);

		switch(SSL_get_error(ssl, r)) {
			// Data was written to the wire
			case SSL_ERROR_NONE:
				totalSent += r;
				bytesLeft -= r;
				printf("writeData() Wrote %u bytes, %u remaining\n", totalSent, bytesLeft);
				break;

			// WOULDBLOCK
			case SSL_ERROR_WANT_WRITE:
				break;

			case SSL_ERROR_WANT_READ:
				break;

			// Possible error?
			default:
				break;
		}
	}

	// Check to see if the connection was closed or there was a problem sending the data. Either way, DC
	if((r == 0) || (SSL_get_shutdown(ssl) != 0)) {
		printf("Server closed the connection or there was a write error\n");
		clientRunning = false;
	}

	// If data was written, print it out
	if(totalSent > 0) {
		printf("Wrote %u bytes to server:\n", totalSent);
		for(unsigned int i = 0; i < totalSent; i++) {
			printf("0x%X ", pData[i]);
		}
		printf("\n");
		for(unsigned int i = 0; i < totalSent; i++) {
			printf("%c", pData[i]);
		}
		printf("\n");
	}
}

/**
 * Disconnect
 * Shutdown and close the socket handle, clean up any other resources in use
 */
void SSLClient::disconnect() {
	// Shutdown SSL & Free memory
	SSL_shutdown(ssl);
	SSL_free(ssl);
	if(clientCTX)
		SSL_CTX_free(clientCTX);
	clientRunning = false;

	printf("SSLClient: Client has disconnected from the server.\n");
}

