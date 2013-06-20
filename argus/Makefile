CC = g++
CFLAGS = -o 

prog=activeip_argus_pair_stats activeip_argus_tcpsynack_stats
objs=activeip_argus_pair_stats.o activeip_argus_tcpsynack_stats.o

all: ${prog} 

%.o: %.cc
	${CC} -std=c++0x -c $<
activeip_argus_pair_stats: activeip_argus_pair_stats.o 
	${CC} -o $@ $<
activeip_argus_tcpsynack_stats: activeip_argus_tcpsynack_stats.o 
	${CC} -o $@ $<

clean:
	rm -f ${objs} ${prog}
