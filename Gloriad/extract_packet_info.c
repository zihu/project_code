#include "libtrace.h"
#include <inttypes.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include "lt_inttypes.h"
#include <list>
#include <set>
#include <map>
#include <arpa/inet.h>
using namespace std;

double lastts = 0.0;
double startts = 0.0;
double begints = 0.0;
double endts = 0.0;
double ts = 0.0;
double prets = 0.0;
double curts = 0.0;
uint64_t v4=0;
uint64_t v6=0;
uint64_t udp=0;
uint64_t tcp=0;
uint64_t icmp=0;
uint64_t ok=0;
struct in_addr src_ip, src_ip1;
struct in_addr dst_ip, dst_ip1;
char srcip_buf[256], srcip_buf1[256];
char dstip_buf[256], dstip_buf1[256];


//timestamp srcIP and dstIP tuple. 
struct ts_src_dst
{
  double _ts;
  unsigned long _src;
  unsigned long _dst;
};

//stats information for each IP address
struct stat_info 
{
  unsigned long _tcp_synack_event;
  unsigned long _pair_event;
  unsigned long _srccount;
  unsigned long _dstcount;
  unsigned long _srcbytes;
  unsigned long _dstbytes;
};

list<ts_src_dst> interval_packets;
set<unsigned long> alive_ip_set;
map<unsigned long, stat_info> ip_records;


void update_ip_records(unsigned long src, unsigned long dst, bool is_typsynack, bool is_pair, unsigned short bytes)
{
  struct stat_info temp_record;
  map<unsigned long, stat_info>::iterator mit;
  //update src ip record;
  mit = ip_records.find(src);
  if(mit != ip_records.end())
  {
    (mit->second)._srccount += 1;
    (mit->second)._srcbytes += bytes;
    if(is_typsynack)
      (mit->second)._tcp_synack_event += 1;
    if(is_pair)
      (mit->second)._pair_event += 1;
  }
  else
  {
    memset(&temp_record,0, sizeof(temp_record));
    temp_record._srccount = 1;
    temp_record._dstcount = 0;
    temp_record._srcbytes = bytes;
    temp_record._dstbytes = 0;

    if(is_typsynack)
      temp_record._tcp_synack_event = 1;
    else
      temp_record._tcp_synack_event = 0;
    if(is_pair)
      temp_record._pair_event = 1;
    else
      temp_record._pair_event = 0;
    ip_records.insert(pair<unsigned long, stat_info>(src, temp_record));
  }


  //update dst ip record;
  mit = ip_records.find(dst);
  if(mit != ip_records.end())
  {
    (mit->second)._dstcount += 1;
    (mit->second)._dstbytes += bytes;
  }
  else
  {
    memset(&temp_record,0, sizeof(temp_record));
    temp_record._srccount = 0;
    temp_record._dstcount = 1;
    temp_record._srcbytes = 0;
    temp_record._dstbytes = bytes;
    temp_record._tcp_synack_event = 0;
    temp_record._pair_event = 0;
    ip_records.insert(pair<unsigned long, stat_info>(dst, temp_record));
  }

}


int find_match(unsigned long src, unsigned long dst, double ts, double interval)
{
  list<ts_src_dst>::reverse_iterator it;
  for(it=interval_packets.rbegin(); it!= interval_packets.rend(); ++it)
  {
    if(src == it->_dst && dst == it->_src)
    {
      /*
      memset(srcip_buf, 0, 256);
      memset(dstip_buf, 0, 256);
      strcpy(srcip_buf, inet_ntoa(src_ip));
      strcpy(dstip_buf, inet_ntoa(dst_ip));

      src_ip1.s_addr = it->_src;
      dst_ip1.s_addr = it->_dst;
      memset(srcip_buf1, 0, 256);
      memset(dstip_buf1, 0, 256);
      strcpy(srcip_buf1, inet_ntoa(src_ip1));
      strcpy(dstip_buf1, inet_ntoa(dst_ip1));
      printf("%f\t%s\t%s\t%f\t%s\t%s\n",it->_ts, srcip_buf1, dstip_buf1, ts, srcip_buf, dstip_buf);
      */
      if(ts-it->_ts <= interval)
	return 1;
    }
  }
  return 0;
}


static void per_packet(libtrace_packet_t *packet, const double interval)
{

  // two proof events, TCP SYN+ACK; SRC-DST pair. 
  bool is_tcpsynack = false;
  bool is_pair = false;

  uint64_t bytes = 0;

	/* Packet data */
	uint32_t remaining;
	/* L3 data */
	void *l3;
	uint16_t ethertype;
	/* Transport data */
	void *transport;
	uint8_t proto;
	/* Payload data */
	void *payload;
	libtrace_tcp_t *tcp = NULL;
	libtrace_ip_t *ip = NULL;
	libtrace_icmp_t *icmp = NULL;


	ts = trace_get_seconds(packet);
	bytes = trace_get_wire_length(packet);

	if(startts == 0.0)
	{
	  startts = trace_get_seconds(packet);
	  prets = startts;
	  curts = startts;
	  begints = startts;
	}
	else
	{
	  prets = curts;
	  curts = ts;
	  endts = ts;
	}


 	l3 = trace_get_layer3(packet,&ethertype,&remaining);

	if (!l3)
	{
	  /* Probable ARP or something */
	  return;
	}

	/* Get the UDP/TCP/ICMP header from the IPv4/IPv6 packet */
	switch (ethertype) {
		case 0x0800:
		  	ip = trace_get_ip(packet);
			if(!ip)
			  return;
			else
			{
			  src_ip.s_addr = (ip->ip_src).s_addr;
			  dst_ip.s_addr = (ip->ip_dst).s_addr;
			}
			break;
		default:
			return;
	}

	/* Parse the udp/tcp/icmp payload */
	switch(ip->ip_p) {
		case 1:
		  	icmp = trace_get_icmp(packet);
			if(icmp->type == 0) // || icmp->type == 3 || icmp->type == 5 || icmp->type == 11)
			{
			  //is_alive = true;
			  //ICMP reply/error packet;
			}
			break;
		case 6:
			//tcp = (libtrace_tcp_t*)transport;
			tcp = trace_get_tcp(packet);
			if(tcp && tcp->syn && tcp->ack)
			{
			  is_tcpsynack = true;
			  //syn+ack packet;
			}
			break;
		case 17:
			break;
		default:
			return;
	}

	int tcp_synack = 0;
	if(is_tcpsynack)
	{
	  tcp_synack = 1;
	}
	memset(srcip_buf, 0, 256);
	memset(dstip_buf, 0, 256);
	strcpy(srcip_buf, inet_ntoa(src_ip));
	strcpy(dstip_buf, inet_ntoa(dst_ip));
	printf("%f\t%s\t%02x\t%s\t%02x\t%d\n", ts, srcip_buf, ntohl(src_ip.s_addr), dstip_buf, ntohl(dst_ip.s_addr), tcp_synack);
}

static void usage(char *argv0)
{
	fprintf(stderr,"usage: %s [ --filter | -f bpfexp ]  [ --max-interval | -t interval ]\n\t\t[ --help | -h ] [ --libtrace-help | -H ] libtraceuri...\n",argv0);
}

void print_all_alive_ip()
{
  set<unsigned long>::iterator it;
  struct in_addr alive_ip;
  for(it= alive_ip_set.begin(); it != alive_ip_set.end(); it++)
  {
    alive_ip.s_addr = (*it);
    //printf("%lu\t%s\n",(*it), inet_ntoa(alive_ip));
    printf("%s\n", inet_ntoa(alive_ip));

  }
}

void print_all_ip_statsinfo()
{
  map<unsigned long, stat_info>::iterator mit;
  struct in_addr ip_addr;
  for(mit= ip_records.begin(); mit != ip_records.end(); mit++)
  {
    ip_addr.s_addr = mit->first;
    printf("%02x\t%s\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\n", ntohl(ip_addr.s_addr),inet_ntoa(ip_addr),(mit->second)._tcp_synack_event,(mit->second)._pair_event, (mit->second)._srccount, (mit->second)._dstcount, (mit->second)._srcbytes, (mit->second)._dstbytes );

  }
}


int main(int argc, char *argv[])
{
	libtrace_t *trace;
	libtrace_packet_t *packet;
	libtrace_filter_t *filter=NULL;
	double interval=0.0;

	while(1) {
		int option_index;
		struct option long_options[] = {
			{ "filter",		1, 0, 'f' },
			{ "max-interval",	1, 0, 't' },
			{ "help",		0, 0, 'h' },
			{ "libtrace-help",	0, 0, 'H' },
			{ NULL,			0, 0, 0 }
		};

		int c= getopt_long(argc, argv, "f:t:hH",
				long_options, &option_index);

		if (c==-1)
			break;

		switch (c) {
			case 'f':
				filter=trace_create_filter(optarg);
				break;
			case 't':
				interval=atof(optarg);
				break;
			case 'H':
				trace_help();
				return 1;
			default:
				fprintf(stderr,"Unknown option: %c\n",c);
				/* FALL THRU */
			case 'h':
				usage(argv[0]);
				return 1;
		}
	}

	if (optind>=argc) {
		fprintf(stderr,"Missing input uri\n");
		usage(argv[0]);
		return 1;
	}

	while (optind<argc) {
		trace = trace_create(argv[optind]);
		++optind;

		if (trace_is_err(trace)) {
			trace_perror(trace,"Opening trace file");
			return 1;
		}

		if (filter)
			if (trace_config(trace,TRACE_OPTION_FILTER,filter)) {
				trace_perror(trace,"ignoring: ");
			}

		if (trace_start(trace)) {
			trace_perror(trace,"Starting trace");
			trace_destroy(trace);
			return 1;
		}

		packet = trace_create_packet();

		while (trace_read_packet(trace,packet)>0) {
			per_packet(packet, interval);
		}

		trace_destroy_packet(packet);

		if (trace_is_err(trace)) {
			trace_perror(trace,"Reading packets");
		}

		trace_destroy(trace);
	}

	printf("%f\t%f\n",startts, endts );
	return 0;
}
