#!/bin/bash 
# by Zi: zihu@usc.edu
# this script tries to split/move traces to each 15 minutes time bin. 
# if trace doesn't cross bins, just move it to the right bin
# otherwise, we have to split the trace and put different parts to different bins


# bin time range
INTERVAL=900 
INPUTFILE=$1
ACTIVEIP_STATDIR="/home/zihu/activeip_stat"
GET_F_L_TS_BIN="$ACTIVEIP_STATDIR/get_f_l_ts"
STATUS_FN="$ACTIVEIP_STATDIR/cur_bin_status"
ALL_STATUS_RECORD="$ACTIVEIP_STATDIR/all_bin_records.dat"
ALL_TRACES_RECORD="$ACTIVEIP_STATDIR/all_traces_records.dat"

#record all the traces processed
echo $INPUTFILE >> $ALL_TRACES_RECORD

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

exit 0
