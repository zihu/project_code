CC = g++
#CFLAGS += -pg -I/home/samfs-02/LANDER/plander/include -g -Wall
#LDFLAGS = -pg -lpcap -lz -lbz2 -lpthread
CFLAGS += -I/home/samfs-02/LANDER/plander/include -g -Wall
LDFLAGS = -lpcap -lz -lbz2 -lpthread

LDLIBS = -L /home/samfs-02/LANDER/plander/lib -ltrace

#want to link static, hence below
PLANDER_LIBDIR = /home/samfs-02/LANDER/plander/lib
TRACELIBS = $(PLANDER_LIBDIR)/libtrace.a $(PLANDER_LIBDIR)/libwandio.a
LDLIBS = 

default: all

all: activeip_metric_stats get_f_l_ts

clean:
	rm -f *~ *.o activeip_metric_stats

activeip_metric_stats: activeip_metric_stats.o $(TRACELIBS)

get_f_l_ts: get_f_l_ts.o $(TRACELIBS)
