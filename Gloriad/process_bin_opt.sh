#!/bin/bash 
# by Zi: zihu@usc.edu
# this script does one thing: process traces, if a bin get all the necessary traces, process it.

ACTIVEIP_STATDIR="/home/samfs-02/LANDER/zihu/activeip_stat"
[ -d "$ACTIVEIP_STATDIR" ] || exit 1 

#function for processing traces
#take a bin directory as input, sort all erf files and process them one by one
ACTIVEIP_STATS_BIN="$ACTIVEIP_STATDIR/activeip_metric_stats_opt"
[ -e "$ACTIVEIP_STATS_BIN" ] || exit 1

PROCESS_TRACES="$ACTIVEIP_STATDIR/bin_opt.log"

process_bin()
{
  S_TIME=$(date "+%Y%m%d-%H%M%S")
  local bin_dir=$1
  local RSLT_OD="$ACTIVEIP_STATDIR/TEST_RSLT_OPT"
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
  #echo $args

  #feed sorted erf file list to the processing code
  err=$( 2>&1 >$TMPOUT $ACTIVEIP_STATS_BIN $args )
  if [ "$?" != "0" ]; then
    echo "$err" >$TMPERR
    return 0
  fi
  E_TIME=$(date "+%Y%m%d-%H%M%S")
  #record all the traces processed and the processing time
  echo $S_TIME $E_TIME $bin_dir >> $PROCESS_TRACES

  #compress the result file
  # delete the bin directory after it is processed.
  #/bin/rm -rf $bin_dir
  return 1
}

process_bin $1
mv gmon.out gmon_opt.out
