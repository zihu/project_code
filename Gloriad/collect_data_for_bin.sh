#!/bin/bash 
# this script tries to collect all traces for each 15 minutes time bin. 

#the time length of each bin is 900 seconds.
INTERVAL=300 

INPUTFILE=$1
#ACTIVEIP_STATDIR="/home/zihu/aliveip_stat"
ACTIVEIP_STATDIR="/home/zihu/Projects/project_code/Gloriad"
ACTIVEIP_STATS_BIN="$ACTIVEIP_STATDIR/get_f_l_ts"
STATUS_FN="$ACTIVEIP_STATDIR/cur_status"

BIN_TMP_DIR="$ACTIVEIP_STATDIR/bin_temp_data"
[ -d "$BIN_TMP_DIR" ] || mkdir -p "$BIN_TMP_DIR"


#extract lander name:
dirname=${INPUTFILE%/*}
landername=${dirname##*/}
basename=${INPUTFILE##*/}

OD="$ACTIVEIP_STATDIR/tmp/$landername"
[ -d "$OD" ] || mkdir -p "$OD"

BIN_DATA_DIR="$ACTIVEIP_STATDIR/bin_data/$landername"
[ -d "$BIN_DATA_DIR" ] || mkdir -p "$BIN_DATA_DIR"


TRACE_SPLIT="$ACTIVEIP_STATDIR/tracesplit"
TRACE_MERGE="$ACTIVEIP_STATDIR/tracemerge"

TMPOUT=$OD/$basename.stats
TMPERR=$OD/$basename.stats.err

# get start time and end time of the trace
st_end_t=$(2>$TMPERR $ACTIVEIP_STATS_BIN "erf:$INPUTFILE" )
if [ "$?" != "0" ]; then
 	echo "get start and end time of the trace failed" >>$TMPERR
	exit 1
fi

TRACE_ST=$(echo $st_end_t | awk '{print $1}')
TRACE_ET=$(echo $st_end_t | awk '{print $2}')
TRACE_SEQN=$(echo $basename | awk -F'-' '{print $3}')
echo $TRACE_ST $TRACE_ET $TRACE_SEQN


# check if the status file exist?
# the status file content: bin_start_time bin_end_time previous_file_seq#
BIN_ST=0
BIN_ET=0


merge_traces()
{
  MTRACE="erf:"$1
  CMD_STR=""
  while read trace
  do
    CMD_STR=$CMD_STR" erf:"$BIN_TMP_DIR/$trace
  done <<< "$(ls $BIN_TMP_DIR)"
  $TRACE_MERGE $MTRACE $CMD_STR
}

if [ -e "$STATUS_FN" ]; then
  STATUS_INFO=$(cat $STATUS_FN)
  BIN_ST=$(echo $STATUS_INFO | awk '{print $1}')
  BIN_ET=$(echo $STATUS_INFO | awk '{print $2}')
  SEQNO=$(echo $STATUS_INFO | awk '{print $3}')
  BIN_ST_SEC=$(echo $BIN_ST | awk -F'.' '{print $1}')
  BIN_ET_SEC=$(echo $BIN_ET | awk -F'.' '{print $1}')
  MTRACE_FN=$BIN_ST_SEC"-"$BIN_ET_SEC"-"$SEQNO

  PRE_SEQN=$(echo $STATUS_INFO | awk '{print $3}')
  CMP_EST=`echo "$TRACE_ET >= $BIN_ST" | bc`
  CMP_EET=`echo "$TRACE_ET <= $BIN_ET" | bc`
  CMP_SST=`echo "$TRACE_ST >= $BIN_ST" | bc`
  CMP_SET=`echo "$TRACE_ST <= $BIN_ET" | bc`

  echo $BIN_ST $BIN_ET $TRACE_ST $TRACE_ET
  if [ $CMP_SST -eq 1 ] && [ $CMP_EET -eq 1 ];then
# trace belong to the bin, mv the trace to place for further processing
    cp $INPUTFILE $BIN_TMP_DIR
  elif [ $CMP_SST -eq 0 ] && [ $CMP_EET -eq 1 ]; then
# part of trace belong to the bin, keep second part of the trace
# split the trace, move the second part to place
    PARTIALTRACE=$BIN_TMP_DIR/$basename"_p2"
    echo $PARTIALTRACE
    2>>$TMPERR $TRACE_SPLIT -s $BIN_ST "erf:$INPUTFILE" "erf:$PARTIALTRACE"
  elif [ $CMP_SST -eq 1 ] && [ $CMP_EET -eq 0 ]; then
# part of trace belong to the bin,  keep first half of the trace
# split the trace, move the first part to place
    PARTIALTRACE=$BIN_TMP_DIR/$basename"_p1"
    echo $PARTIALTRACE
    2>>$TMPERR $TRACE_SPLIT -e $BIN_ET "erf:$INPUTFILE" "erf:$PARTIALTRACE"
# merge all traces for the current bin and move it to another directory for processing
    MTRACE=$BIN_DATA_DIR/$MTRACE_FN
    echo "merge traces" $MTRACE
    merge_traces $MTRACE
# delete traces of the current bin
    /bin/rm -rf $BIN_TMP_DIR/*
# start the new bin and put the second half of current trace into this bin
    PARTIALTRACE=$BIN_TMP_DIR/$basename"_p2"
    2>>$TMPERR $TRACE_SPLIT -s $BIN_ET "erf:$INPUTFILE" "erf:$PARTIALTRACE"
# update the status file
    BIN_ST=$BIN_ET
    BIN_ET=`echo "$BIN_ST + $INTERVAL" | bc`
    echo -e "$BIN_ST\t$BIN_ET\t$TRACE_SEQN" > $STATUS_FN
  elif [ $CMP_SET -eq 0]; then
# should start new bin,
# merge all traces for the previous bin and move it to another directory for processing.
    echo "start new bin"

  fi
else
# status file doesn't exist, start new bin. 
  BIN_ST=$TRACE_ST
  BIN_ET=`echo "$BIN_ST + $INTERVAL" | bc`
  PRE_SEQN=$TRACE_SEQN
  echo -e "$BIN_ST\t$BIN_ET\t$PRE_SEQN" > $STATUS_FN
  cp $INPUTFILE $BIN_TMP_DIR
fi


#CMP_RSLT=`echo "$ST < $ET" | bc`
#if [ $CMP_RSLT ];then
#  echo $ST $ET
#fi

