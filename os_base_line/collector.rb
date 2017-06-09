#! /usr/bin/env ruby
#

require 'json'

# data var
#
cmd_list = 	[
		"passwd",
		"portmap",
		"login",
		"ps",
		"sshd",
		"bash",
		"ifconfig",
		"ls",
		"netstat",
		"ps",
		"top",
		"syslogd",
		"tcpdump",
		"gcc"
		]

STAFF_ACCOUNT_SIMULATION	=[
				"zhang.san",
				"li.si",
				"wang.wu",
				"zhao.liu"
				]

#
#
#
def get_hostname()
	`hostname`.chomp
end

HOST = get_hostname

#重要文件md5
#
# 1.获取命令路径
def get_path(cmd)
	path = `which #{cmd} 2>/dev/null`.chomp
end


# 2.计算文件md5
def get_md5(path)
	return "null" if path == ""
	md5sum = `md5sum #{path}|awk '{print $1}'`.chomp

end

#p get_md5(get_path('ls'))

# 3.批量计算文件md5，返回在数组中
def get_cmds_md5(cmd_list)
	ret = []
	cmd_list.each{|cmd|
		md5sum = get_md5(path = get_path(cmd))
		ret << {"cmd" => cmd, "path"=> path, "md5" => md5sum}
	}
	return ret	
end


#
# 获取model模块信息
def get_mod_info()
	mods = `lsmod`.split("\n")[1..-1]
	mod_info = []
	mods.each{|each|
		mod,size,used,by = each.split("\s")
		mod_info << {"mod" => mod, "size" => size, "used" => used, "by" => by}
	}
	mod_info
end

#
# 获取账户信息
#
def get_account_info()
	user_list = `cat /etc/passwd`.split("\n")
	account_info = []
	user_list.each{|each|
		loginname,passwd,uid,gid,username,homedir,shell = each.chomp.split(":")
		account_info <<	{
				"loginname" 	=> loginname,
				"passwd"	=> passwd,
				"uid"		=> uid,
				"gid"		=> gid,
				"username"	=> username,
				"homedir"	=> homedir,
				"shell"		=> shell
				}

	}
	account_info
end

#
# 获取用户组信息
#
def get_group_info()
	group_list = `cat /etc/group`.split("\n")
	group_info = []
	group_list.each{|each|
		groupname,passwd,org_num,userlist = each.chomp.split(":")
		group_info <<	{
				"groupname" 	=> groupname,
				"passwd"	=> passwd,
				"org_num"	=> org_num,
				"userlist"	=> userlist,
				}

	}
	group_info
end

#
# 获取登录口令信息（口令密文已经被隐去）
#
def get_shadow_info()
	shadow_list = `cat /etc/shadow`.split("\n")
	shadow_info = []
	shadow_list.each{|each|
		username,passwd_flag,last_change_pwd = each.chomp.split(":")[0..2]
		shadow_info <<	{
				"username" 		=> username,
				"passwd_flag"		=> passwd_flag =~ /\$/?'******':passwd_flag,
				"last_change_pwd"	=> last_change_pwd,
				}

	}
	shadow_info
end

#
#对比两个数据机构（数组格式）对应字段，对比当key的值一样的时候，value的值是否也一样
# Array input_data, Array compared_data, String compared_key, String compared_value
def compare(input_data, compared_data, compared_key, compared_value)
	input_hash,compared_hash,ret = {},{},{}

	input_data.each{|each|
		input_hash.store(each[compared_key],each[compared_value])
	}

	compared_data.each{|each|
		compared_hash.store(each[compared_key],each[compared_value])
	}

	input_hash.each{|k,v|
		ret.store(k,v) unless compared_hash[k] == v
	}
	ret
end

#
#
# Int level, String who, String did, String what
#
def warn(level, event, other)
	lable = ["INFO","NOTICE","WARNING","CRITCAL"]
	puts "    [#{lable[level]}]  #{Time.now}  #{HOST}  #{event}  #{other}"
end
baseline = JSON::parse File.new('tmp','r').read

#
# 找到md5不一样的cmd ELF文件
# Array cmd_list, Hash baseline
#
def find_changed_cmd(cmd_list,baseline)
	cmds_md5	= get_cmds_md5(cmd_list) 
	res = compare(cmds_md5,baseline,"cmd","md5")
	if res.size > 0
		res.each{|cmd,md5|
			warn(2, "\"#{cmd}\" command has chaneged.", "md5sum:#{md5}")
		}
	else
		puts "No command was changed."
	end
end

#find_changed_cmd(cmd_list, baseline["cmds_md5"])

#
# 找出增加的用户
# Hash account_info, Hash baseline
def find_added_user(account_info, baseline)
	input_array,compare_array = [],[]
	account_info.each{|each| input_array << each["loginname"]}
	baseline.each{|each| compare_array << each["loginname"]}
	res = input_array-compare_array

	# 去掉员工名单中的用户
	res = res - STAFF_ACCOUNT_SIMULATION
	if res.size>0
		res.each{|each|	  warn(1,"出现不在员工名单的用户","#{each}")}
	else
		puts "没有增加的异常用户。"
	end
end

# find_added_user(get_account_info,baseline["account_info"])

def find_changed_uid(account_info,baseline)
       	res = compare(account_info, baseline, "loginname", "uid")	
        if res.size > 0
                res.each{|user,uid|
                        warn(2, "\"#{uid}\" The uid has chaneged.", "username:#{user}")
                }
        else
                puts "No user or uid were changed."
        end
end

#find_changed_uid(get_account_info(), baseline["account_info"])


def find_changed_shell(account_info,baseline)
       	res = compare(account_info, baseline, "loginname", "shell")	
        if res.size > 0
                res.each{|user,shell|
                        warn(2, "\"#{shell}\" The shell has chaneged.", "username:#{user}")
                }
        else
                puts "No user or shell were changed."
        end
end

# find_changed_shell(get_account_info(), baseline["account_info"])

def is_pwd_setted(shadow_info)
	shadow_info.each{|each|
		next if each["username"] == "root"
		unless each["passwd_flag"] =~ /\*|!|!!/
			warn(2,"用户#{each["username"]}被设置了登录密码。","")
		end
	}
end

#is_pwd_setted(baseline["shadow_info"])


def is_change_pwd_yestoday(shadow_info)
	today = Time.new.to_i/86400
	shadow_info.each{|each|
		if today - each["last_change_pwd"].to_i < 2
			warn(2,"用户#{each["username"]}在一天内更改了登录密码。","")
		end
	}
end
# is_change_pwd_yestoday(baseline["shadow_info"])

def is_new_group_added(group_info,baseline)
	input_group,output_group = [],[]
	group_info.each{|each| input_group << each["groupname"]}
	baseline.each{|each| output_group << each["groupname"]}
	res = input_group - output_group
	if res.size > 0
		res.each{|each|
			warn(1, "A new group \"#{each}\" was added.", "group:#{each}")
		}
	end
end

#is_new_group_added(get_group_info(),baseline["group_info"])

def is_group_member_changed(groupinfo, baseline)
        res = compare(groupinfo, baseline, "groupname", "userlist")
        if res.size > 0
                res.each{|groupname,userlist|
                        warn(2, "Members of gourp \"#{groupname}\" has chaneged.", "userlist:#{userlist}")
                }
        else
                puts "No group were changed."
        end

end

#is_group_member_changed(get_group_info(),baseline["group_info"])

def is_new_mod_added(mod_info,baseline)
	input_mod,output_mod = [],[]
	mod_info.each{|each| input_mod << each["mod"]}
	baseline.each{|each| output_mod << each["mod"]}
	res = input_mod - output_mod
	if res.size > 0
                res.each{|each|
                        warn(1, "A new model \"#{each}\" was added.", "modelname:#{each}")
                }
        end
end

#is_new_mod_added(get_mod_info,baseline["mod_info"])
#exit


# --main--

if ARGV[0] == "--check"
  # 获取关键命令的md5
  #
  puts JSON::pretty_generate cmds_md5	= get_cmds_md5(cmd_list) 
  
  #puts ',"mod_info":'
  
  #获取model模块信息
  #
  puts JSON::pretty_generate mod_info	= get_mod_info()
  #puts ',"account_info":'
  
  #获取账户信息
  #
  puts JSON::pretty_generate account_info	= get_account_info()
  #puts ',"group_info":'
  
  #获取用户组信息
  #
  puts JSON::pretty_generate group_info	= get_group_info()
  #puts ',"shadow_info":'
  
  #获取用户口令信息
  #
  puts JSON::pretty_generate shadow_info	= get_shadow_info()
  
  #puts '}'
  
  baseline = JSON::parse File.new('tmp','r').read
end

if ARGV[0] == "--audit"
	puts "\n**********************OS BASELINE AUDIT*************************\n\n"
	
	puts "\n<== Find changed command ==>"
	find_changed_cmd(cmd_list, baseline["cmds_md5"])
	
	puts "\n<== Find added user ==>"
	find_added_user(get_account_info,baseline["account_info"])
	
	puts "\n<== Find changed UID ==>"
	find_changed_uid(get_account_info(), baseline["account_info"])
	
	puts "\n<== Find changed shell ==>"
	find_changed_shell(get_account_info(), baseline["account_info"])
	
	puts "\n<== Find setted password ==>"
	is_pwd_setted(baseline["shadow_info"])
	
	puts "\n<== Find changed password in oneday ==>"
	is_change_pwd_yestoday(baseline["shadow_info"])
	
	puts "\n<== Find a new added group ==>"
	is_new_group_added(get_group_info(),baseline["group_info"])
	
	puts "\n<== Find a group that changed member ==>"
	is_group_member_changed(get_group_info(),baseline["group_info"])
	
	puts "\n<== Find a new added model ==>"
	is_new_mod_added(get_mod_info,baseline["mod_info"])

end
