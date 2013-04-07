#!/bin/bash 
# by Zi: zihu@usc.edu
# this script tries to merge traces in a bin. 
# if any bin directory has been modified since the last $MAX_WAIT_TIME, we merge all the traces in the bin directory
# move the merged trace to another directory for further processing and remove the bin

MAX_WAIT_TIME=1800
BIN_DIR="$1"
[ -d "$BIN_DIR" ] || exit 0 


ACTIVEIP_STATDIR="/home/zihu/activeip_stat"
ALL_MERGED_DIR_RECORD="$ACTIVEIP_STATDIR/all_merged_bin_records.dat"
TRACE_MERGE="$ACTIVEIP_STATDIR/tracemerge"

#extract lander name:
landername=${BIN_DIR##*/}

MERGED_BIN_DIR="$ACTIVEIP_STATDIR/bin_data/$landername"
[ -d "$MERGED_BIN_DIR" ] || mkdir -p "$MERGED_BIN_DIR"


# merge all traces in a given directory
merge_traces()
{
  MTRACE="erf:"$1
  BIN_DIR_W_TRACES="$2"
  FILES=$(ls $BIN_DIR_W_TRACES)

  if [ -z "$FILES" ];then
    return
  fi

  CMD_STR=""
  while read trace
  do
    CMD_STR=$CMD_STR" erf:"$BIN_DIR_W_TRACES/$trace
  done <<< "$(ls $BIN_DIR_W_TRACES)"
  $TRACE_MERGE $MTRACE $CMD_STR
}

DIRS=$(ls $BIN_DIR)
[ "$DIRS" ] || exit 0

MERGE_TIME=$(date "+%Y%m%d-%H%M%S")
while read BIN_TRACES_DIR
do
  traces_dir=$BIN_DIR/$BIN_TRACES_DIR
  modtime=$(stat -c%Y $traces_dir)
  now=$(date +%s)
  gap=`echo "$now - $modtime" | bc`
  #echo $BIN_TRACES_DIR $modtime $now $gap $MAX_WAIT_TIME >> $ALL_MERGED_DIR_RECORD
  if [ $gap -lt $MAX_WAIT_TIME ]; then # too young, continue to wait.
    continue
  else
    #merge the traces in the directory
    merged_trace_base=$BIN_TRACES_DIR"-"$now
    merged_trace=$MERGED_BIN_DIR/$merged_trace_base
    #echo $BIN_TRACES_DIR $merged_trace $traces_dir
    merge_traces $merged_trace $traces_dir
    echo $MERGE_TIME $BIN_TRACES_DIR $merged_trace >> $ALL_MERGED_DIR_RECORD
    /bin/rm -rf $traces_dir
  fi
done <<< "$(ls $BIN_DIR)"
