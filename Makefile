CXX = g++
CXXFLAGS = -Wall -O2 -pthread
LDLIBS = -lnetfilter_queue

TARGET = client

OBJS = main.o \
       client_control.o \
       client_tun.o \
       client_socket.o \
       client_parser.o \
       client_raw.o \
       client_nfqueue.o \
       hb_headers.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

main.o: main.cpp client.h
	$(CXX) $(CXXFLAGS) -c main.cpp

client_control.o: client_control.cpp client.h
	$(CXX) $(CXXFLAGS) -c client_control.cpp

client_tun.o: client_tun.cpp client.h
	$(CXX) $(CXXFLAGS) -c client_tun.cpp

client_socket.o: client_socket.cpp client.h
	$(CXX) $(CXXFLAGS) -c client_socket.cpp

client_parser.o: client_parser.cpp client.h
	$(CXX) $(CXXFLAGS) -c client_parser.cpp

client_raw.o: client_raw.cpp client.h hb_headers.h
	$(CXX) $(CXXFLAGS) -c client_raw.cpp

client_nfqueue.o: client_nfqueue.cpp client.h hb_headers.h
	$(CXX) $(CXXFLAGS) -c client_nfqueue.cpp

hb_headers.o: hb_headers.cpp hb_headers.h
	$(CXX) $(CXXFLAGS) -c hb_headers.cpp

clean:
	rm -f $(OBJS) $(TARGET)