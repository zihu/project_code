#!/bin/bash 
INPUTFILE=$1

ACTIVEIP_STATDIR="/home/zihu/activeip_stat"
ACTIVEIP_STATS_BIN="$ACTIVEIP_STATDIR/activeip_metric_stats"
PROCESS_TRACES="$ACTIVEIP_STATDIR/all_processed_bins.dat"


#extract lander name:
dirname=${INPUTFILE%/*}
landername=${dirname##*/}
basename=${INPUTFILE##*/}

OD="$ACTIVEIP_STATDIR/RSLT/$landername"
[ -d "$OD" ] || mkdir -p "$OD"
RSLT_FN=$basename".stats"
TMPOUT=$OD/$RSLT_FN
TMPERR=$OD/$basename.stats.err
RSLT_GZ_FN=$RSLT_FN".tar.gz"

echo $INPUTFILE >> $PROCESS_TRACES
err=$( 2>&1 >$TMPOUT $ACTIVEIP_STATS_BIN -t 1 erf:$INPUTFILE )
cd $OD && tar -zcf $RSLT_GZ_FN $RSLT_FN && rm $RSLT_FN

if [ "$?" != "0" ]; then
	echo "$err" >$TMPERR
	exit 1
fi

exit 0
