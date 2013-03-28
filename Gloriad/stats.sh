!/bin/bash 
INPUTFILE=$1

ALIVEIP_STATDIR="/home/zihu/aliveip_stat"
ALIVEIP_STATS_BIN="$ALIVEIP_STATDIR/aliveip_stats"

#extract lander name:
dirname=${INPUTFILE%/*}
landername=${dirname##*/}
basename=${INPUTFILE##*/}

OD="$ALIVEIP_STATDIR/tmp/$landername"
[ -d "$OD" ] || mkdir -p "$OD"
TMPOUT=$OD/$basename.stats
TMPERR=$OD/$basename.stats.err

err=$( 2>&1 >$TMPOUT $ALIVEIP_STATS_BIN -t 1 erf:$INPUTFILE )
if [ "$?" != "0" ]; then
#rm -f $TMPOUT
	echo "$err" >$TMPERR
	exit 1
fi

#stats output:
#active ip addresses
