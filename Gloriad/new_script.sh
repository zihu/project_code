#!/bin/bash 
# by Zi: zihu@usc.edu
# this script does one thing: process traces, if a bin get all the necessary traces, process it.
INPUTFILE=$1

ACTIVEIP_STATDIR="/home/samfs-02/LANDER/zihu/activeip_stat"
[ -d "$ACTIVEIP_STATDIR" ] || exit 1 

#function for processing traces
#take a bin directory as input, sort all erf files and process them one by one
#EXE_FN="activeip_metric_stats_old"
EXE_FN="activeip_metric_stats_opt"
ACTIVEIP_STATS_BIN="$ACTIVEIP_STATDIR/$EXE_FN"
[ -e "$ACTIVEIP_STATS_BIN" ] || exit 1

GET_TIME_BIN="$ACTIVEIP_STATDIR/get_f_l_ts"
[ -e "$GET_TIME_BIN" ] || exit 1


time_log="$ACTIVEIP_STATDIR/time_new.log"

process_bin()
{
  local bin_dir=$1
  local RSLT_OD="$ACTIVEIP_STATDIR/TIME_RSLT"
  [ -d "$RSLT_OD" ] || mkdir -p "$RSLT_OD"
  local td_basename=${bin_dir##*/}
  local RSLT_FN=$td_basename".stats"
  local TMPOUT=$RSLT_OD/$td_basename".stats"
  local TMPERR=$RSLT_OD/$td_basename".err"
  local RSLT_FN_GZ=$RSLT_FN".tar.gz"
  local args="-t 1"
  #sort erf files, and construct the args list
  while read trace
  do
   p_trace="$bin_dir/$trace"
   args="$args $p_trace" 
  done <<< "$(ls $bin_dir | grep "^201.*" | sort )"

  S_TIME=$(date "+%Y%m%d-%H%M%S")
  #feed sorted erf file list to the processing code
  $ACTIVEIP_STATS_BIN $args > /dev/null
  E_TIME=$(date "+%Y%m%d-%H%M%S")
  echo "time for my script: " $S_TIME $E_TIME $bin_dir >> $time_log

  #compress the result file
  # delete the bin directory after it is processed.
  #/bin/rm -rf $bin_dir
  #mv gmon.out $EXE_FN"_gmon.out" 
  return 1
}

b_dir="$ACTIVEIP_STATDIR/test_bin2"
process_bin $b_dir
