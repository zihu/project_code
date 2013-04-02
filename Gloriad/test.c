#include <stdio.h>
#include <stdlib.h>
#include <map>
#include <set>
#include <arpa/inet.h>

using namespace std;
struct stat_info
{
  unsigned long _ip;
  set<unsigned long> _uniq_ips;
};

int main(int argc, char**argv)
{
  char *ip_str="50.22.100.250";
  unsigned long ip_int=inet_addr(ip_str);
  printf("%s:%lu\n",ip_str, htonl(ip_int));
  struct in_addr ip_addr;
  ip_addr.s_addr = ip_int;

  printf("%s:%s\n",ip_str, inet_ntoa(ip_addr));
  printf("%02x\n", htonl(ip_int));
}

/*
int main(int argc, char** argv)
{
  set<unsigned long> uniq_ips;
  set<unsigned long>* uniq_ips_copy;
  set<unsigned long> uniq_ips_test;

  map< unsigned long, stat_info > ip_stat;

  uniq_ips.insert(20);
  struct stat_info temp;
  temp._ip = 1;
  temp._uniq_ips.insert(20);
  ip_stat.insert(pair<unsigned long, stat_info>(1, temp));

  uniq_ips_copy = &(ip_stat[1]._uniq_ips);
  uniq_ips_test = ip_stat[1]._uniq_ips;
  printf("%d\n", uniq_ips_copy->size());
  printf("%d\n", uniq_ips_test.size());
  uniq_ips_test.insert(10);
  printf("%d\n", uniq_ips_copy->size());
  printf("%d\n", uniq_ips_test.size());
  uniq_ips_copy->insert(30);
  printf("%d\n", (ip_stat[1]._uniq_ips).size());

}
*/


/*
int main(int argc, char** argv)
{
  set<unsigned long> uniq_ips;
  set<unsigned long>* uniq_ips_copy;
  map< unsigned long, set<unsigned long> > ip_uniq_ips;
  uniq_ips.insert(20);
  ip_uniq_ips.insert(pair<unsigned long, set<unsigned long> >(1, uniq_ips));
  uniq_ips_copy = &(ip_uniq_ips[1]);
  printf("%d\n", uniq_ips_copy->size());
  ip_uniq_ips[1].insert(30);
  printf("%d\n", uniq_ips_copy->size());


}
*/

