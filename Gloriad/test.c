#include<stdio.h>
#include<stdlib.h>
int main(int argc, char** argv)
{
  double ts=atof(argv[1]);
  double ts1 = 1364406598.999679;
  if (ts< ts1)
    printf("ts1:%f\n", ts1);
  else
    printf("ts:%f\n", ts);

}
