#! /usr/bin/bash
pid=`ls /proc/|grep "[0-9]\{1,\}"`
for each in $pid
	do
	#pid:ppid:sid:start_time:path:mode:owner:group:uid:euid:suid:gid:egid:sgidcmd:modify_time:is_sockit:pgid:env
	ret=`cat /proc/$each/stat 2>/dev/null|awk '{print $1":"$4":"$6}' 2>/dev/null`
	#ret=`cat /proc/$each/stat |awk '{print $1":"$4":"$6":"}' 2>/dev/null`
	# echo $(getconf CLK_TCK)
	ret=$ret:`awk -v ticks="$(getconf CLK_TCK)" 'NR==1 { now=$1; next }    { print strftime("%s",now - ($22/ticks)) }' /proc/uptime /proc/$each/stat 2>/dev/null`
	path=`readlink /proc/$each/exe`
        list_file_info=`ls -l $path`

        #if [ -z $list_file_info6 ]
        if [ -z "$list_file_info" ]
        then
                continue
        fi

	#get stat
	if [ -z $path ]
	then
		mode_owner_group='::'
		modify_time=''
	else
 		mode_owner_group=`ls -l $path|awk '{print $1":"$3":"$4}'`
		modify_time=`stat $path -c %Y`
	fi
	ret=$ret:$path:$mode_owner_group
	uid_euid_suid=`grep  "Uid" /proc/$each/status 2>/dev/null|awk '{print $2":"$3":"$4}' `
	gid_egid_sgid=`grep  "Gid" /proc/$each/status 2>/dev/null|awk '{print $2":"$3":"$4}' `

	cmd=`cat /proc/$each/cmdline 2>/dev/null|base64`
	
	ret=$ret:$uid_euid_suid:$gid_egid_sgid:$cmd
#	ret=$ret:$cmd
	env=`cat /proc/$each/environ 2>/dev/null|base64`
	fd=`ls -l /proc/$each/fd 2>/dev/null|grep -i socket`
	if [ -z "$fd" ]
		then
		is_socket=0
	else
		is_socket=1
	fi
	pgid=`cat /proc/$each/stat 2>/dev/null|awk '{print $5}' 2>/dev/null`
	comm=`cat /proc/$each/comm 2>/dev/null`
	echo $ret:$modify_time:$is_socket:$pgid:$env:$comm
done
