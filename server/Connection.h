/**
   ssltests
   Connection.h
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

#ifndef _connection_h_
#define _connection_h_

#include <iostream>
#include <stdio.h>

#include <boost/thread.hpp>

#include <openssl/ssl.h>

class Connection {
private:
	BIO* m_bio;
	SSL* m_ssl;
	bool m_connected;

	boost::thread* m_thread;
	boost::mutex m_runMutex;

private:
	void disconnect();
	void readData();
	void writeData(char*, unsigned int);

public:
	Connection(BIO*, SSL*);
	~Connection();
	
	void start();
	void stop();
	void operator() ();
};

#endif