CXX = g++
CXXFLAGS = -Wall -std=c++17 -O2
LDFLAGS = -lpcap

SRCS = main.cpp PacketSniffer.cpp
OBJS = $(SRCS:.cpp=.o)
TARGET = packet_sniffer

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	-rm -f $(OBJS) $(TARGET)
