#launch dapscoin-cli
#launch dapscoind 
PID=0

checkstatus () {
     echo "Checking dapascoind status"
     messagesleep 1
     PID=$(pgrep dapscoind)
     if [ -z $PID ]
     then 
         return -1
     else 
         return $PID
     fi 
     echo "Status Return Code:='"$PID"'"
} 

getpid() {
  echo $(pgrep dapscoind) 
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

start () {
     echo "Attempting dapscoind Start"
     PID=$(pgrep dapscoind)
     if ! [ -z $PID ]
     then 
       echo "dapscoind already started on PID='"$PID"'" 
       return $PID
     else 
       dapscoind --daemon 
       messagesleep 7
       checkstatus
       echo "dapscoind started on PID='"$PID"'"
       PID=$(pgrep dapscoind)
       return $PID
     fi 
} 

resync () {
     echo "Attempting dapscoind resync"
     PID=$(pgrep dapscoind)
     if ! [ -z $PID ]
     then 
       echo "dapscoind already started on PID='"$PID"'" 
       return $PID
     else 
       dapscoind -resync 
       messagesleep 7
       checkstatus
       echo "dapscoind sresync issued and successful tarted on PID='"$PID"'"
       PID=$(pgrep dapscoind)
       return $PID
     fi 
} 

stop () {
    echo "Attempting dapscoind Stop"
    PID=$(pgrep dapscoind)
     if ! [ -z $PID ]
          then     
            echo "Stop dapscoind PID='"$PID"'" 
            echo "Stop Execution : gracefully"
            dapscoin-cli stop
            messagesleep 7
            checkstatus
            echo "dapscoind successfully stopped @PID='"$PID"'" 
          else
            echo "dapscoind is not executiing: "     
    fi
}

restart () {
    echo "Attempting dapscoind Restart"
    PID=$(pgrep dapscoind)
    if ! [ -z $PID ]
    then  
          stop 
          checkstatus
          if  [ -z $PID ]
          then     
             echo "dapscoind ending... :"      
          fi 
     fi 
     start
     checkstatus
     PID=$(pgrep dapscoind)
     return $PID
} 

case $1 in
     status) 
          echo "Retrieving Status" 
          checkstatus
          if ! [ -z $PID ]
          then     
            echo "Normal execution and responsive PID='"$PID"'"
          else
            echo "dapscoind is not executing :" $PID     
          fi  
          ;;     
     restart) 
          echo "Restarting dapscoind"
          checkstatus
          if ! [ -z $PID ]
          then     
            echo echo "dapscoind not running"
            messagesleep 7
            start
            checkstatus
            dapscoind --daemon
          else
            echo "dapscoind is executing on process ID: " $PID
            echo "Stopping dapscoind @ PID:"$PID " Before "
            stop
            checkstatus
            messagesleep 7

          fi  
          ;;
     start)
          echo "launch dapscoind: start"
          checkstatus
          if [ -z $PID ]
          then     
            echo "Starting dapscoind --daemon"
            dapscoind --daemon
            echo "dapscoind executing as PID:" $PID 
            messagesleep 7
          else
            echo "dapscoind is executing on process ID: " $PID
            echo "Start aborting - please try launchdaps.sh restart"     
          fi  
          ;; 
     stop)
          echo "Shutting down dapscoind: Stop"
          checkstatus          
          stop
          ;;
     getpid)
          getpid       
          ;;        
     *)
          echo "Invalid input - '"$1"'"
          echo "Valid switches : start, stop, restart, status, resync"
          ;;
esac
 


