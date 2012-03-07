/**
   ssltests
   Connection.cpp
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

#include "Connection.h"

Connection::Connection(BIO* b, SSL* s) {
	m_bio = b;
	m_ssl = s;
	m_connected = false;
	m_thread = NULL;
}

Connection::~Connection() {
	if(m_bio)
		BIO_free(m_bio);
	if(m_thread != NULL)
		delete m_thread;
}

void Connection::start() {
	m_runMutex.lock();
	if(m_connected) {
		std::cout << "Connection: improperly calling start()!\n";
		m_connected = false;
	} else {
		m_connected = true;
	}
	m_runMutex.unlock();

	m_thread = new boost::thread(boost::ref(*this));
}

void Connection::stop() {
	m_runMutex.lock();
	m_connected = false;
	m_runMutex.unlock();
}

void Connection::operator() () {
	std::cout << "Connection thread spawned..\n";

	bool connected = true;
	// Thread must be spawned with m_connected as true
	m_runMutex.lock();
	connected = m_connected;
	m_runMutex.unlock();

	if(!connected) {
		std::cout << "Connection thread spawned in disconnected state, aborting\n";
		return;
	}

	// Main loop
	while(connected) {
		readData();

		// update connected state
		m_runMutex.lock();
		connected = m_connected;
		m_runMutex.unlock();

		// Yield remainder of time slice to other threads
		boost::this_thread::yield();
	}

	disconnect();
}

void Connection::disconnect() {
	std::cout << "Connection Disconnecting\n";
	// Shutdown and Free SSL objects
	SSL_shutdown(m_ssl);
	SSL_free(m_ssl);
	m_runMutex.lock();
	m_connected = false;
	m_runMutex.unlock();
}

void Connection::readData() {
	int r = 0;
	unsigned int bytesRead = 0, maxLen = 4096;
	char *pData = new char[maxLen];

	// Loop and grab all data on the wire
	do {
		bytesRead += r;
		r = SSL_read(m_ssl, pData+bytesRead, maxLen-bytesRead);
	} while(r > 0);

	// Check to see if the connection was closed
	if((r == 0) || (SSL_get_shutdown(m_ssl) != 0)) {
		std::cout << "Client closed the connection\n";
		m_runMutex.lock();
		m_connected = false;
		m_runMutex.unlock();
	}
	
	// If data was read, print it out and write it back
	if(bytesRead > 0) {
		std::cout << "Received " << bytesRead << " bytes from client:\n";
		for(unsigned int i = 0; i < bytesRead; i++) {
			printf("0x%X ", pData[i]);
		}
		std::cout << "\n";
		for(unsigned int i = 0; i < bytesRead; i++) {
			printf("%c", pData[i]);
		}
		std::cout << "\n";

		// Send the data back
		writeData(pData, bytesRead);
	}

	delete [] pData;
}

void Connection::writeData(char* pData, unsigned int len) {
	int r = 0;

	// Write data to the wire
	r = SSL_write(m_ssl, pData, len);

	// Check to see if the connection was closed or there was a problem sending the data. Either way, DC
	if((r <= 0) || (SSL_get_shutdown(m_ssl) != 0)) {
		std::cout << "Client closed the connection or there was a write error\n";
		m_runMutex.lock();
		m_connected = false;
		m_runMutex.unlock();
	}

	// If data was written, print it out
	if(r > 0) {
		std::cout << "Wrote " << len << " bytes to client:\n";
		for(unsigned int i = 0; i < len; i++) {
			printf("0x%X ", pData[i]);
		}
		std::cout << "\n";
		for(unsigned int i = 0; i < len; i++) {
			printf("%c", pData[i]);
		}
		std::cout << "\n";
	}
}


