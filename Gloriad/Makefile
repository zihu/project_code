CC = g++
GCC = gcc
CFLAGS += -std=c++0x -I/home/samfs-02/LANDER/plander/include -g -Wall
LDFLAGS = -lpcap -lz -lbz2 -lpthread
LDLIBS = -L /home/samfs-02/LANDER/plander/lib -ltrace

#want to link static, hence below
PLANDER_LIBDIR = /home/samfs-02/LANDER/plander/lib
TRACELIBS = $(PLANDER_LIBDIR)/libtrace.a $(PLANDER_LIBDIR)/libwandio.a
LDLIBS = 

default: all

prog = activeip_metric_stats_opt get_f_l_ts tracesplit

all: ${prog}
clean:
	rm -f *~ *.o ${prog} 

tracesplit: tracesplit.o ${TRACELIBS}
	${GCC} ${LDFLAGS} $^ -o $@ 
tracesplit.o: tracesplit.c
	${GCC} -I/home/samfs-02/LANDER/plander/include -g -Wall -c tracesplit.c 

activeip_metric_stats_opt: activeip_metric_stats_opt.o $(TRACELIBS)

get_f_l_ts: get_f_l_ts.o ${TRACELIBS}


