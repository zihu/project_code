#!/bin/bash
#trace="bin_tmp_data/landeri2/19691231-160000/20130528-053933-00738776-hcFaGEc"
##trace="bin_tmp_data/landeri2/20130528-234500/20130529-064534-00741512-hcFaGEc"
#./get_f_l_ts $trace
#if [ "$?" == "0" ]; then
#  echo "succ"
#else
#  echo "fail"
#fi



#trace="bin_tmp_data/landeri2/20130528-234500/20130529-064534-00741512-hcFaGEc"
trace="bin_tmp_data/landeri2/19691231-160000/20130528-053933-00738776-hcFaGEc"
# get start time and end time of the trace
st_end_t=$(2>/dev/null ./get_f_l_ts "erf:$trace" )
if [ "$?" != "0" ]; then 
  exit 1
fi

TRACE_ST=$(echo $st_end_t | awk '{print $1}')
TRACE_ET=$(echo $st_end_t | awk '{print $2}')

bad_trace=`echo "$TRACE_ST < 0" | bc`
if [ $bad_trace -eq 1 ];then
  echo "bad trace 1" 
fi

#time now?
N_TIME_S=$(date +%s)
name="hello"
echo $name"_$N_TIME_S"

# two days?
DAY_SEC=172800
DIFF_DELAY=`echo "$N_TIME_S - $TRACE_ST" | bc`

bad_trace=`echo "$DIFF_DELAY > $DAY_SEC" | bc`

echo $TRACE_ST $TRACE_ET $DIFF_DELAY
if [ $bad_trace -eq 1 ];then
  echo "bad trace 2" 
fi
