/**
   ssltests
   main.cpp
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

#include <stdio.h>
#include <signal.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>

#include "SSLServer.h"

bool canRun;

// Handles an unix terminiation signals (Ctrl C)
void sighandler(int sig) {
	canRun = false;
}

int main (int argc, const char * argv[])
{
	// Register sighandler for terminiation signals:
	signal(SIGABRT, &sighandler);
	signal(SIGINT, &sighandler);
	signal(SIGTERM, &sighandler);

	// Init SSL
	if(!SSL_library_init()) {
		printf("SSL library init failed\n");
		return -1;
	}

	SSL_load_error_strings();
	RAND_load_file("/dev/urandom", 1024); // Seed the PRNG

	// Init and run the server
	SSLServer* svr = new SSLServer();
	canRun = svr->init();
	while(canRun)
		svr->run();
	delete svr;

	return 0;
}
