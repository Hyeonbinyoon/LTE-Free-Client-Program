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
       client_udp.o \
       hb_headers.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.cpp client.h hb_headers.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)