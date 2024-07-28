LDLIBS += -lpcap

all: pcap-test-hw

pcap-test: pcap-test-hw.c

clean:
	rm -f pcap-test-hw *.o
