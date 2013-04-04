#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <list>
#include <vector>
#include <set>
#include <map>
#include <arpa/inet.h>

#define MAX_BUF_SIZE 256
using namespace std;

double lastts = 0.0;
double startts = 0.0;
double begints = 0.0;
double endts = 0.0;
double ts = 0.0;
double prets = 0.0;
double curts = 0.0;
struct in_addr src_ip, src_ip1;
struct in_addr dst_ip, dst_ip1;
char srcip_buf[256], srcip_buf1[256];
char dstip_buf[256], dstip_buf1[256];


void SplitString(char* cStr, char* cDelim, vector<char *> &sItemVec)
{
    char *p;
    p=strtok(cStr,cDelim);
    while (p!=NULL)
    {
       sItemVec.push_back(p);
       p=strtok(NULL,cDelim);
    }
}

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
  set<unsigned long> _uniq_end_set;
  set<unsigned long> _uniq_dst_set;
  set<unsigned long> _uniq_src_set;
};

list<ts_src_dst> interval_packets;
//map< pair<unsigned long, unsigned, long>, >
set<unsigned long> alive_ip_set;
map<unsigned long, stat_info> ip_records;
//map<unsigned long, set<unsigned long> > srcip_uniq_ips;
//map<unsigned long, set<unsigned long> > dstip_uniq_ips; 

void update_ip_records(unsigned long src, unsigned long dst, bool is_typsynack, bool is_pair, unsigned short bytes)
{

  set<unsigned long>::iterator uniq_endset_sit;
  set<unsigned long>* uniq_end_set;
  //update dst -> source set

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
    //update src -> unique destination set
    ((mit->second)._uniq_end_set).insert(dst);
    ((mit->second)._uniq_dst_set).insert(dst);


    /*
    uniq_end_set = &((mit->second)._uniq_end_set);
    uniq_endset_sit = uniq_end_set->find(dst);
    if(uniq_endset_sit == uniq_end_set->end())
    {
      uniq_end_set->insert(dst);
    }
    */

  }
  else
  {
    temp_record._srccount = 1;
    temp_record._dstcount = 0;
    temp_record._srcbytes = bytes;
    temp_record._dstbytes = 0;
    (temp_record._uniq_end_set).insert(dst);
    (temp_record._uniq_dst_set).insert(dst);
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
    //update dst -> source set
    ((mit->second)._uniq_end_set).insert(src);
    ((mit->second)._uniq_src_set).insert(src);
  }
  else
  {
    temp_record._srccount = 0;
    temp_record._dstcount = 1;
    temp_record._srcbytes = 0;
    temp_record._dstbytes = bytes;
    temp_record._tcp_synack_event = 0;
    temp_record._pair_event = 0;
    (temp_record._uniq_end_set).insert(src);
    (temp_record._uniq_src_set).insert(src);
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


static void per_packet(char* packet_info, const double interval)
{


  // two proof events, TCP SYN+ACK; SRC-DST pair. 
  char delim[]="\t ";
  bool is_tcpsynack = false;
  bool is_pair = false;

  //printf("%s\n", packet_info);
  vector<char *> packet_tuple;
  SplitString(packet_info, delim , packet_tuple);
  //printf("%s\t%s\n", packet_tuple[1], packet_tuple[2]);
  if(packet_tuple.size()!=5)
    return;

  double ts = atof(packet_tuple[0]);
  unsigned long src = htonl(atol(packet_tuple[1]));
  unsigned long dst = htonl(atol(packet_tuple[2]));
  int tcp_synack = atoi(packet_tuple[3]);
  int bytes = atoi(packet_tuple[4]);

  if(tcp_synack==1)
    is_tcpsynack = true;

  if(src==0 || dst ==0)
    return;


  if(startts == 0.0)
  {
    startts = ts;
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


  src_ip.s_addr = src;
  dst_ip.s_addr = dst;
  
  //test if exists any match of packets in the time range.
  if(find_match(src_ip.s_addr, dst_ip.s_addr,ts, interval)==1)
    is_pair=true;
  
  //push to the queue if ts-startts < interval; otherwise, pop the oldest, and push the new one. 
  ts_src_dst temp_item;
  temp_item._ts = ts;
  temp_item._src = src_ip.s_addr;
  temp_item._dst = dst_ip.s_addr;
  if( (ts-(interval_packets.front())._ts) <= interval)
  {
    interval_packets.push_back(temp_item);
  }
  else
  {
    //pop out all the old tuple that exceed the time interval. 
    while(!interval_packets.empty())
    {
      interval_packets.pop_front();
      if((ts-(interval_packets.front())._ts) < interval)
        break;
    }
    interval_packets.push_back(temp_item);
  
  }

  //update stats info for both the src and dst ip in this packet. 
  update_ip_records(src_ip.s_addr, dst_ip.s_addr, is_tcpsynack, is_pair, bytes);

}

static void usage(char *argv0)
{
	fprintf(stderr,"usage: %s  [ --max-interval | -t interval ]\n\t\t[ --help | -h ] processed_trace...\n",argv0);
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
    printf("%02x\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\n", ntohl(ip_addr.s_addr),(mit->second)._tcp_synack_event,(mit->second)._pair_event, (mit->second)._srccount, (mit->second)._dstcount, (mit->second)._srcbytes, (mit->second)._dstbytes, ((mit->second)._uniq_end_set).size(), ((mit->second)._uniq_dst_set).size(), ((mit->second)._uniq_src_set).size());
  }
}


int main(int argc, char *argv[])
{
	double interval=0.0;

	while(1) {
		int option_index;
		struct option long_options[] = {
			{ "max-interval",	1, 0, 't' },
			{ "help",		0, 0, 'h' },
			{ "libtrace-help",	0, 0, 'H' },
			{ NULL,			0, 0, 0 }
		};

		int c= getopt_long(argc, argv, "t:hH",
				long_options, &option_index);

		if (c==-1)
			break;

		switch (c) {
			case 't':
				interval=atof(optarg);
				break;
			case 'H':
				usage(argv[0]);
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

	char buf[MAX_BUF_SIZE];
	while (optind<argc) 
	{
	  FILE* trace_fp =fopen(argv[optind], "r");
	  if(!trace_fp)
	  {
	    printf("Can not open the file:%s\n", argv[optind]);
	    return 1;
	  }

	  while(!feof(trace_fp))
	  {
	    memset(buf,0, MAX_BUF_SIZE);
	    if(fgets(buf, MAX_BUF_SIZE, trace_fp))
	    {
	      buf[strlen(buf)-1]='\0';
	      per_packet(buf, interval);
	    }
	  }
	  fclose(trace_fp);
	  optind++;
	}

	//print out all alive IP in the set
	//print_all_alive_ip();


	//print the start time and end time of this data file;
	//printf("#%f\t%f\n", begints, endts);


	//print fsdb header
	printf("#fsdb ip_hex tcp_synack_events pair_events pkts_count_as_src pkts_count_as_dst bytes_count_as_src bytes_count_as_dst uniq_end_count uniq_dst_count uniq_src_count\n");

	//print the stats info of all ip addresses in this data file
	print_all_ip_statsinfo();

	//clear all containers. 
	//alive_ip_set.clear();
	interval_packets.clear();
	ip_records.clear();

	return 0;
}
