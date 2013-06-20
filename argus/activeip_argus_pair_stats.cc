#include <inttypes.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <list>
#include <vector>
#include <set>
#include <map>
#include <unordered_map>
#include <unordered_set>
//#include <boost/functional/hash.hpp>
#include <arpa/inet.h>
using namespace std;

typedef unsigned long ulong;
typedef unsigned int uint;
typedef unsigned short ushort ;
#define MAX_BUF_SIZE 1024

void SplitString(char* cStr, char* cDelim, vector<string> &sItemVec)
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
  unsigned long _src_flow_count;
  unsigned long _dst_flow_count;
  unsigned long _srccount;
  unsigned long _dstcount;
  unsigned long _srcbytes;
  unsigned long _dstbytes;
  unordered_set<unsigned long> _uniq_end_set;
  unordered_set<unsigned long> _uniq_dst_set;
  unordered_set<unsigned long> _uniq_src_set;
};


unordered_map<unsigned long, stat_info> ip_records;
unordered_map<unsigned long, unsigned long> ip_synack_counts;

void update_ip_tcpsynack_events(unsigned long ip, unsigned long counts)
{
  //update ip tcpsynack events map; 
  unordered_map<unsigned long, unsigned long>::iterator mit;
  mit = ip_synack_counts.find(ip);
  if(mit != ip_synack_counts.end())
  {
    mit->second = counts;
  }
  else
  {
    ip_synack_counts.insert(pair<unsigned long, unsigned long>(ip, counts));
  }

}



void update_ip_records(unsigned long src, unsigned long dst, uint64_t sbytes, uint64_t dbytes, uint64_t spkts, uint64_t dpkts)
{
  unsigned long tcp_synack_event_count=0;
  //update dst -> source set
  unordered_map<unsigned long, stat_info>::iterator mit;
  unordered_map<unsigned long, unsigned long>::iterator sait;
  
  //update src ip record;
  mit = ip_records.find(src);
  if(mit != ip_records.end())
  {
    (mit->second)._srccount += spkts;
    (mit->second)._srcbytes += sbytes;
    (mit->second)._dstcount += dpkts;
    (mit->second)._dstbytes += dbytes;
    (mit->second)._src_flow_count += 1;
    if(spkts>1)
      (mit->second)._pair_event += 1;

    //update src -> unique destination set
    ((mit->second)._uniq_end_set).insert(dst);
    ((mit->second)._uniq_dst_set).insert(dst);
  }
  else
  {
    sait=ip_synack_counts.find(src);
    if(sait !=ip_synack_counts.end())
    {
      tcp_synack_event_count=sait->second;
    }
    else
    {
      tcp_synack_event_count=0;
    }

    struct stat_info temp_record;
    //memset(&temp_record, 0, sizeof(struct stat_info));
    temp_record._srccount = spkts;
    temp_record._srcbytes = sbytes;
    temp_record._dstcount = dpkts;
    temp_record._dstbytes = dbytes;
    temp_record._src_flow_count = 1;
    temp_record._dst_flow_count = 0;
    (temp_record._uniq_end_set).insert(dst);
    (temp_record._uniq_dst_set).insert(dst);
    temp_record._tcp_synack_event = tcp_synack_event_count;

    if(spkts>1)
      temp_record._pair_event = 1;
    else
      temp_record._pair_event = 0;
    ip_records.insert(pair<unsigned long, stat_info>(src, temp_record));
  }


  mit = ip_records.find(dst);
  if(mit != ip_records.end())
  {

    (mit->second)._srccount += dpkts;
    (mit->second)._srcbytes += dbytes;
    (mit->second)._dstcount += spkts;
    (mit->second)._dstbytes += sbytes;
    (mit->second)._dst_flow_count += 1;
    if(dpkts>0)
      (mit->second)._pair_event += 1;

    //update dst -> source set
    ((mit->second)._uniq_end_set).insert(src);
    ((mit->second)._uniq_src_set).insert(src);
  }
  else
  {

    struct stat_info temp_record;

    sait=ip_synack_counts.find(dst);
    if(sait !=ip_synack_counts.end())
    {
      tcp_synack_event_count=sait->second;
    }
    else
    {
      tcp_synack_event_count=0;
    }

    //memset(&temp_record, 0, sizeof(struct stat_info));
    temp_record._srccount = dpkts;
    temp_record._dstcount = spkts;
    temp_record._srcbytes = dbytes;
    temp_record._dstbytes = sbytes;
    temp_record._src_flow_count = 0;
    temp_record._dst_flow_count = 1;
    (temp_record._uniq_end_set).insert(src);
    (temp_record._uniq_src_set).insert(src);
    temp_record._tcp_synack_event = tcp_synack_event_count;

    if(dpkts>0)
    	temp_record._pair_event = 1;
    else
      	temp_record._pair_event = 0;

    ip_records.insert(pair<unsigned long, stat_info>(dst, temp_record));
  }

}



static void per_flow(char *flow_info)
{
  // two proof events, TCP SYN+ACK; SRC-DST pair. 
  uint64_t sbytes = 0;
  uint64_t dbytes = 0;
  uint64_t spkts = 0;
  uint64_t dpkts = 0;
  unsigned long sip = 0;
  unsigned long dip = 0;

  //parse the flow information
  char delim[]=" \t";
  vector<string> sItem;
  sItem.clear();
  SplitString(flow_info,delim,sItem);
  if(sItem.size()!=6)
    return;

  struct in_addr src_ip, dst_ip;
  int err=inet_aton(sItem[0].c_str(), &src_ip);
  int err2=inet_aton(sItem[1].c_str(), &dst_ip);
  if(err == 0 || err2 == 0)
    return;

  //printf("%s\n", inet_ntoa(src_ip));

  //get pkts count and bytes count
  spkts = atoi(sItem[2].c_str());
  dpkts = atoi(sItem[3].c_str());
  sbytes = atoi(sItem[4].c_str());
  dbytes = atoi(sItem[5].c_str());

  //printf("%s\t%lu\t%lu\t%lu\n", inet_ntoa(src_ip), spkts, dpkts, sbytes);

  //update stats info for both the src and dst ip in this packet. 
  update_ip_records(ntohl(src_ip.s_addr), ntohl(dst_ip.s_addr), sbytes, dbytes, spkts, dpkts);
}



static void usage(char *argv0)
{
	fprintf(stderr,"usage: %s [ --filter | -f bpfexp ]  [ --max-interval | -t interval ]\n\t\t[ --help | -h ] [ --libtrace-help | -H ] libtraceuri...\n",argv0);
}

void print_all_ip_statsinfo()
{
  unordered_map<unsigned long, stat_info>::iterator mit;
  struct in_addr ip_addr;
  for(mit= ip_records.begin(); mit != ip_records.end(); mit++)
  {
    ip_addr.s_addr = htonl(mit->first);
    //printf("%02x\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\n", ip_addr.s_addr,(mit->second)._tcp_synack_event,(mit->second)._pair_event, (mit->second)._srccount, (mit->second)._dstcount, (mit->second)._srcbytes, (mit->second)._dstbytes, ((mit->second)._uniq_end_set).size(), ((mit->second)._uniq_dst_set).size(), ((mit->second)._uniq_src_set).size());

    printf("%s\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\n", inet_ntoa(ip_addr),(mit->second)._tcp_synack_event,(mit->second)._pair_event, (mit->second)._srccount, (mit->second)._dstcount, (mit->second)._srcbytes, (mit->second)._dstbytes, ((mit->second)._uniq_end_set).size(), ((mit->second)._uniq_dst_set).size(), ((mit->second)._uniq_src_set).size());

  }
}

void get_tcp_synack_events(char* fn)
{

  FILE*fp = fopen(fn, "r");
  if(!fp)
    printf("open file: %s failed\n", fn);

  char buf[MAX_BUF_SIZE];
  memset(buf,0,MAX_BUF_SIZE);
  while (fgets(buf, MAX_BUF_SIZE, fp)) 
  {
    buf[strlen(buf)-1]='\0';
    char delim[]=" \t";
    vector<string> sItem;
    sItem.clear();
    SplitString(buf,delim,sItem);
    if(sItem.size()!=2)
      continue;

    struct in_addr ip;
    unsigned long count;
    count=atol(sItem[1].c_str());
    int err=inet_aton(sItem[0].c_str(), &ip);
    if(err == 0)
      continue;
    update_ip_tcpsynack_events(ntohl(ip.s_addr), count);
    memset(buf, 0, MAX_BUF_SIZE);
  }
}

int main(int argc, char *argv[])
{
	double interval=0.0;
	char *tcp_synack_iplist_fn=NULL;
	char buf[MAX_BUF_SIZE];
	memset(buf,0,MAX_BUF_SIZE);
	while(1) {
		int option_index;
		struct option long_options[] = {
			{ "max-interval",	1, 0, 't' },
			{ "help",		0, 0, 'h' },
			{ "tcp_synack_iplist",  0, 0, 'i' },
			{ NULL,			0, 0, 0 }
		};

		int c= getopt_long(argc, argv, "t:i:h",
				long_options, &option_index);

		if (c==-1)
			break;

		switch (c) {
			case 't':
				interval=atof(optarg);
				break;
			case 'i':
				tcp_synack_iplist_fn=strdup(optarg);
				break;
			default:
				fprintf(stderr,"Unknown option: %c\n",c);
				/* FALL THRU */
			case 'h':
				usage(argv[0]);
				return 1;
		}
	}

	if(tcp_synack_iplist_fn)
	{
	  get_tcp_synack_events(tcp_synack_iplist_fn);
	}
	else
	{
	  ip_synack_counts.clear();
	}

	while (fgets(buf, MAX_BUF_SIZE, stdin)) 
	{
	  buf[strlen(buf)-1]='\0';
	  per_flow(buf);
	  memset(buf, 0, MAX_BUF_SIZE);
	}


	//print the start time and end time of this data file;
	//printf("#trace start:%f\ttrace end:%f\tduration:%f\n", begints, endts, (endts-begints));


	//print fsdb header
	printf("#fsdb ip_hex tcp_synack_events pair_events pkts_count_as_src pkts_count_as_dst bytes_count_as_src bytes_count_as_dst uniq_end_count uniq_dst_count uniq_src_count\n");

	//print the stats info of all ip addresses in this data file
	print_all_ip_statsinfo();

	//clear all containers. 
	ip_records.clear();
	ip_synack_counts.clear();

	free(tcp_synack_iplist_fn);
	return 0;
}
