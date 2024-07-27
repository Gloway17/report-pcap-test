LDLIBS += -lpcap

all: report-pcap-test

pcap-test: report-pcap-test.c

clean:
	rm -f report-pcap-test *.o