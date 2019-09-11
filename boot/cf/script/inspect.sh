#launch dapscoin-cli
#launch dapscoind 
PID=0

checkstatus () {
     PID=$(pgrep dapscoind)
     if pgrep -q dapscoind 
     then 
         return $PID
     else 
         return $PID
     fi 
} 

messagesleep () {
  x=0;   
  echo -n "Waiting"
  while [ $x -lt $1 ]
  do
   echo -n "."
   sleep 1
   echo -n "."
   x=$[$x+1]
  done
  echo ""
}

case $1 in
     status) 
          checkstatus
          if ! [ -z $PID ]
          then     
            echo "Normal execution and responsive PID='"$PID"'"
          else
            echo "dapscoind is not executing :" $PID     
          fi  
          ;;     
     restart) 
          checkstatus
          if [ -z $PID ]
          then     
            echo echo " dapscoind --daemon"
            dapscoind --daemon
          else
            echo "dapscoind is executing on process ID: " $PID
            echo "Kill PID:"$PID 
            dapscoin-cli stop
            messagesleep 7
            echo "Restarting dapscoind"
            dapscoind --daemon 
            messagesleep 7
            checkstatus
            if ! [ -z $PID ]
            then     
               echo "Normal execution and responsive PID='"$PID"'"
            else
               echo "dapscoind not  responsive ending... :" 
               exit -1     
            fi 
          fi  
          ;;
     start)
          echo "Going start"
          checkstatus
          if [ -z $PID ]
          then     
            echo "Starting dapscoind --daemon"
            dapscoind --daemon
            echo "dapscoind executing as PID:" $PID 
            messagesleep 7
          else
            echo "dapscoind is executing on process ID: " $PID
            echo "Start aborting - please try launch.sh restart"     
          fi  
          ;; 
     stop)
          echo "Going Stop"
          checkstatus          
          if ! [ -z $PID ]
          then     
            echo "Stop dapscoind PID:" $PID 
            echo "Stop Execution : gracefully"
            dapscoin-cli stop
            messagesleep 7
          else
            echo "dapscoind is executing on process ID: " $PID
            echo "Aborting Start - please try launch.sh restart"     
          fi   
          ;;     
     *)
          echo "Invalid input - '"$1"'" m,
          echo "Valid switches : start, stop, restart, status "
          ;;
esac
 


