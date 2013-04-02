#!/bin/bash
#compare_result=`echo "2.2 < 1.1" | bc`
#echo $compare_result
#if [ $compare_result -eq 1 ];then
#  echo "hello"
#fi
#
#if [ $compare_result -eq 0 ];then
#  echo "world" 
#fi

#TRACE_DIR="/home/zihu/Projects/project_code/Gloriad/bin_temp_data"
#TRACE_DST_DIR="/home/zihu/Projects/project_code/Gloriad/bin_data"
#MTRACE_FN=" erf:"$TRACE_DST_DIR"/test"
#echo $MTRACE_FN
#
#
#merge_traces()
#{
#  CMD_STR=""
#  while read trace
#  do
#    CMD_STR=$CMD_STR" erf:"$TRACE_DIR/$trace
#  done <<< "$(ls $TRACE_DIR)"
#  echo $CMD_STR
#  tracemerge $MTRACE_FN $CMD_STR
#}
#
#merge_traces

STR=$(ls test_dir)
if [ -n "$STR" ]; then
  echo "not empty"
else
  echo "empty"
fi
