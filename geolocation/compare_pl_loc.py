#!/usr/bin/python
import sys
import math
from geopy import distance

pl_loc_map={}
pl_loc_map2={}


def initial_target_geoloc(target_geo_fn):
    target_geo_fp = open(target_geo_fn)
    target_geo_list= target_geo_fp.readlines()
    target_geo_fp.close()
    for target_geo in target_geo_list:
	target_geo=target_geo.rstrip()
	if target_geo[0][0]=='#':
		continue
	target_geo_tuple=target_geo.split("|")
	geo_info=[]
	geo_info.append(target_geo_tuple[1])
	geo_info.append(target_geo_tuple[2])
	pl_loc_map[target_geo_tuple[0]]=geo_info

def initial_target_geoloc2(target_geo_fn):
    target_geo_fp = open(target_geo_fn)
    target_geo_list= target_geo_fp.readlines()
    target_geo_fp.close()
    for target_geo in target_geo_list:
	target_geo=target_geo.rstrip()
	if target_geo[0][0]=='#':
		continue
	target_geo_tuple=target_geo.split()
	geo_info=[]
	geo_info.append(target_geo_tuple[2])
	geo_info.append(target_geo_tuple[3])
	pl_loc_map2[target_geo_tuple[0]]=geo_info


def compute_error_dist():
    for ip, loc in pl_loc_map2.iteritems():
	loc2=pl_loc_map.get(ip,'N/A')
	if loc2 == 'N/A':
	  continue
	err_dist=(distance.distance(loc,loc2).miles)*1.60934
	print ip +"\t"+str(err_dist)+"\t"+loc[0]+"\t"+loc[1]+"\t"+loc2[0]+"\t"+loc2[1];

if __name__ == "__main__":
    if len(sys.argv)< 3:
  	print sys.argv[0]+" pl_loc_file1 pl_loc_file2"
	exit(0)
    initial_target_geoloc(sys.argv[1])
    initial_target_geoloc2(sys.argv[2])
    compute_error_dist()
