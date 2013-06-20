#!/bin/bash 
# by Zi: zihu@usc.edu
# this script tries to split/move traces to each 15 minutes time bin. 
# if trace doesn't cross bins, just move it to the right bin
# otherwise, we have to split the trace and put different parts to different bins

# bin time range
INTERVAL=900 
INPUTFILE=$1
ACTIVEIP_STATDIR="/home/samfs-02/LANDER/zihu/activeip_stat"
GET_F_L_TS_BIN="$ACTIVEIP_STATDIR/get_f_l_ts"
STATUS_FN="$ACTIVEIP_STATDIR/cur_bin_status"
ALL_STATUS_RECORD="$ACTIVEIP_STATDIR/all_bin_records.dat"
ALL_TRACES_RECORD="$ACTIVEIP_STATDIR/all_traces_records.dat"

PROCESS_TIME_BEFORE=$(date "+%Y%m%d-%H%M%S")

#extract lander name:
dirname=${INPUTFILE%/*}
landername=${dirname##*/}
basename=${INPUTFILE##*/}

BIN_TMP_DIR="$ACTIVEIP_STATDIR/bin_tmp_data/$landername"
[ -d "$BIN_TMP_DIR" ] || mkdir -p "$BIN_TMP_DIR"

OD="$ACTIVEIP_STATDIR/log/$landername"
[ -d "$OD" ] || mkdir -p "$OD"

TRACE_SPLIT="$ACTIVEIP_STATDIR/tracesplit"
TRACE_MERGE="$ACTIVEIP_STATDIR/tracemerge"

TMPDEBUG=$OD/"activeip_stats.debug"
TMPERR=$OD/$basename.stats.err


# get start time and end time of the trace
st_end_t=$(2>$TMPERR $GET_F_L_TS_BIN "erf:$INPUTFILE" )
if [ "$?" != "0" ]; then
 	echo "get start and end time of the trace failed" >>$TMPDEBUG
	exit 1
fi

TRACE_ST=$(echo $st_end_t | awk '{print $1}')
TRACE_ET=$(echo $st_end_t | awk '{print $2}')
TRACE_SEQN=$(echo $basename | awk -F'-' '{print $3}')
TRACE_KEY=$(echo $basename | awk -F'-' '{print $4}')


echo "----------------------------------------------" >> $TMPDEBUG
echo "$basename $TRACE_ST $TRACE_ET $TRACE_SEQN" >> $TMPDEBUG

# caculate which bin this trace should go to
BIN_INDEX_S=`echo "$TRACE_ST / $INTERVAL" | bc`
BIN_INDEX_E=`echo "$TRACE_ET / $INTERVAL" | bc`
DIFF_BIN=`echo "$BIN_INDEX_E - $BIN_INDEX_S" | bc`

if [ $DIFF_BIN -lt 0 ]; then
  echo "bad trace:" $INPUTFILE >> $TMPDEBUG
  exit 1
elif [ $DIFF_BIN -eq 0 ]; then
  # trace doesn't cross bin; move the trace to that bin;
  TRACE_BIN_ST=`echo "$BIN_INDEX_S * $INTERVAL " | bc`
  TRACE_BIN_ET=`echo "($BIN_INDEX_S + 1) * $INTERVAL " | bc`

  BIN_FN_BASE=`date -d @$TRACE_BIN_ST "+%Y%m%d-%H%M%S"`
  BIN_INDEX_DIR="$BIN_TMP_DIR/$BIN_FN_BASE"
  echo "Trace:$basename  Bin:$BIN_FN_BASE $TRACE_BIN_ST $TRACE_BIN_ET" >> $TMPDEBUG
  [ -d "$BIN_INDEX_DIR" ] || mkdir -p "$BIN_INDEX_DIR"
  /bin/cp $INPUTFILE  $BIN_INDEX_DIR
else 
  # trace cross bins, split the trace and move segments to corresponding bins.
  while [ $BIN_INDEX_S -le $BIN_INDEX_E ] 
  do
    TRACE_BIN_ST=`echo "$BIN_INDEX_S * $INTERVAL " | bc` 
    TRACE_BIN_ET=`echo "($BIN_INDEX_S + 1) * $INTERVAL " | bc`
    BIN_FN_BASE=`date -d @$TRACE_BIN_ST "+%Y%m%d-%H%M%S"`
    BIN_INDEX_DIR="$BIN_TMP_DIR/$BIN_FN_BASE"
    echo "Trace:$basename  Bin:$BIN_FN_BASE $TRACE_BIN_ST $TRACE_BIN_ET" >> $TMPDEBUG
    [ -d "$BIN_INDEX_DIR" ] || mkdir -p "$BIN_INDEX_DIR"
    PARTIALTRACE=$BIN_INDEX_DIR/$basename
    2>>$TMPERR $TRACE_SPLIT -s $TRACE_BIN_ST -e $TRACE_BIN_ET "erf:$INPUTFILE" "erf:$PARTIALTRACE"
    ((BIN_INDEX_S=BIN_INDEX_S+1))
  done
fi

PROCESS_TIME_AFTER=$(date "+%Y%m%d-%H%M%S")
#record all the traces processed
echo $PROCESS_TIME_BEFORE $PROCESS_TIME_AFTER $INPUTFILE >> $ALL_TRACES_RECORD




# merge traces in some bins if necessary
# if any bin directory has been modified since the last $MAX_WAIT_TIME, we merge all the traces in the bin directory
# move the merged trace to another directory for further processing,  and remove the bin
ALL_MERGED_DIR_RECORD="$ACTIVEIP_STATDIR/all_merged_bin_records.dat"
MAX_LOCK_ALIVE_TIME=1800
LOCK_DIR="$ACTIVEIP_STATDIR/.merge_lock_dir"
MERGE_TIME=$(date "+%Y%m%d-%H%M%S")
# if the lock dir is too old, may be something is wrong, delete it to free the lock
lock_modtime=$(stat -c%Y $LOCK_DIR)
lock_now=$(date +%s)
lock_gap=`echo "$lock_now - $lock_modtime" | bc`

if [ $loc_gap -gt $MAX_LOCK_ALIVE_TIME ]; then # the lock dir is too old, delete it.
  echo "$MERGE_TIME the lock is too old: $lock_modtime, now: $lock_now, gap: $lock_gap" >> $ALL_MERGED_DIR_RECORD
  /bin/rm -rf $LOCK_DIR
fi

# if other processes are merging traces, exit.
if ! /bin/mkdir $LOCK_DIR >/dev/null 2>&1; then
  echo "$MERGE_TIME try merge file failed due to the lock" >> $ALL_MERGED_DIR_RECORD
  exit 0
fi


BIN_DIR="$BIN_TMP_DIR"
MAX_WAIT_TIME=1200

TRACE_MERGE="$ACTIVEIP_STATDIR/tracemerge"
[ -d "$BIN_DIR" ] || exit 0 
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

    MERGE_TIME_BEFORE=$(date "+%Y%m%d-%H%M%S")
    merged_trace_base=$BIN_TRACES_DIR"-"$now
    merged_trace=$MERGED_BIN_DIR/$merged_trace_base
    #echo $BIN_TRACES_DIR $merged_trace $traces_dir
    merge_traces $merged_trace $traces_dir
    MERGE_TIME_AFTER=$(date "+%Y%m%d-%H%M%S")
    echo $MERGE_TIME $MERGE_TIME_BEFORE $MERGE_TIME_AFTER $BIN_TRACES_DIR $merged_trace >> $ALL_MERGED_DIR_RECORD

    /bin/rm -rf $traces_dir
  fi
done <<< "$(ls $BIN_DIR)"

/bin/rm -rf $LOCK_DIR
exit 0
