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


unordered_map<unsigned long, unsigned long> ip_synack_counts;

void update_ip_records(unsigned long src, unsigned long dst, uint64_t sbytes, uint64_t dbytes, uint64_t spkts, uint64_t dpkts)
{
  //update dst -> source set
  unordered_map<unsigned long, unsigned long>::iterator mit;
  //update dst ip record;
  mit = ip_synack_counts.find(dst);
  if(mit != ip_synack_counts.end())
  {
    mit->second += 1;
  }
  else
  {
    ip_synack_counts.insert(pair<unsigned long, unsigned long>(dst, 1));
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
	fprintf(stderr,"usage: %s [ --help | -h ] flows (one flow per line)...\n",argv0);
}

/*
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
*/

  
void print_all_ip_statsinfo()
{
  unordered_map<unsigned long, unsigned long>::iterator mit;
  struct in_addr ip_addr;
  for(mit= ip_synack_counts.begin(); mit !=ip_synack_counts.end(); mit++)
  {
    ip_addr.s_addr = htonl(mit->first);
    //printf("%02x\t%lu\n", ip_addr.s_addr,mit->second);
    printf("%s\t%lu\n", inet_ntoa(ip_addr),mit->second);
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
			{ "help",		0, 0, 'h' },
			{ NULL,			0, 0, 0 }
		};

		int c= getopt_long(argc, argv, "t:i:h",
				long_options, &option_index);

		if (c==-1)
			break;

		switch (c) {
			default:
				fprintf(stderr,"Unknown option: %c\n",c);
				/* FALL THRU */
			case 'h':
				usage(argv[0]);
				return 1;
		}
	}

	while (fgets(buf, MAX_BUF_SIZE, stdin)) 
	{
	  buf[strlen(buf)-1]='\0';
	  per_flow(buf);
	  memset(buf, 0, MAX_BUF_SIZE);
	}


	//print fsdb header
	printf("#fsdb ip_hex tcp_synack_events\n");

	//print the stats info of all ip addresses in this data file
	print_all_ip_statsinfo();

	//clear all containers. 
	ip_synack_counts.clear();
	free(tcp_synack_iplist_fn);
	return 0;
}
