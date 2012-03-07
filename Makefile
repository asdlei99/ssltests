# Makefile for ssltests

CC = g++
SERVEROBJS = Connection.o SSLServer.o servermain.o
CLIENTOBJS = SSLClient.o clientmain.o
FLAGS = -Iinclude/ -Llib/ -g -Wall
LINK = -lssl -lcrypto -lpthread -lboost_thread-mt

all: client server

client: $(CLIENTOBJS)
	$(CC) $(FLAGS) $(CLIENTOBJS) -o bin/client.exe $(LINK)

server: $(SERVEROBJS)
	$(CC) $(FLAGS) $(SERVEROBJS) -o bin/server.exe $(LINK)

# Server:

Connection.o: server/Connection.cpp
	$(CC) $(FLAGS) -c server/Connection.cpp

SSLServer.o: server/SSLServer.cpp
	$(CC) $(FLAGS) -c server/SSLServer.cpp

servermain.o: server/main.cpp
	$(CC) $(FLAGS) -c server/main.cpp -o servermain.o

# Client:

SSLClient.o: client/SSLClient.cpp
	$(CC) $(FLAGS) -c client/SSLClient.cpp

clientmain.o: client/main.cpp
	$(CC) $(FLAGS) -c client/main.cpp -o clientmain.o

# Other:

clean:
	rm -f *.o *.gch bin/*.exe *~ \#*
