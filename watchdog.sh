#!/bin/bash

 
 



while [ 0 -eq 0 ] 
do

 sleep 5


 

   
 razem="$(ps ax | grep -v grep | grep /elizak_readerx | wc -l)"

 
 echo $razem

 if [ $razem -eq 0 ]
 then

    echo "Program is not running "
    /var/www/elizak_reader/Elizak_Reader/elizakd stop
    sleep 2
   /var/www/elizak_reader/Elizak_Reader/elizakd start
    
 else
    echo "Program is running"
 fi



 



currentTime=`date +"%H%M"`
if [ $currentTime -eq "0502" ]; then 
   echo '' > /var/www/elizak_reader/Elizak_Reader/elizak_watchdog_log  
   echo '' > /var/www/elizak_reader/Elizak_Reader/elizak_log
fi

if [ $currentTime -eq "1402" ]; then 
   echo '' > /var/www/elizak_reader/Elizak_Reader/elizak_watchdog_log  
   echo '' > /var/www/elizak_reader/Elizak_Reader/elizak_log
fi

if [ $currentTime -eq "2102" ]; then 
   echo '' > /var/www/elizak_reader/Elizak_Reader/elizak_watchdog_log  
   echo '' > /var/www/elizak_reader/Elizak_Reader/elizak_log
fi
 

sleep 1
done


echo "End checking...."















