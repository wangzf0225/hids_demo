#! /usr/bin/env ruby
#
require "base64"
#proc_info_file = File.new("./proc_info","r")
proc_info_file = File.new("./test_proc_info","r")

def turn_proc_info_into_hash(file)
	ret = {}
	file.readlines.each{|line|
		each = line.split(':')
		pid = each[0]
		info = {
			"pid"=>         each[0],
			"ppid"=>        each[1],
			"sid"=>         each[2],
			"start_time"=>  each[3],
			"path"=>        each[4],
			"mode"=>        each[5],
			"owner"=>       each[6],
			"group"=>       each[7],
			"uid"=>         each[8],
			"euid"=>        each[9],
			"suid"=>        each[10],
			"gid"=>         each[11],
			"egid"=>        each[12],
			"sgid"=>        each[13],
			"cmd"=>         Base64::decode64(each[14]?each[14]:"").gsub('\x00',''),
			"modify_time"=> each[15],
			"is_socket"=>	each[16],
			"pgid"=>	each[17],
			"env"=>         Base64::decode64(each[18]?each[18]:"").gsub('\x00',''),
			"comm"=>	each[19]
			}
		ret.store(pid,info)
		#break
	}
	ret
end

procs = turn_proc_info_into_hash(proc_info_file)



class ProcCase

	def initialize(proc_hash)
		@proc = proc_hash
		@shell= ["bash","sh","ash","csh","ksh"]
		@program_language=["java","php","python","perl","ruby","lua","go"]
	end
	
	def is_shell()
		@shell.include?(@proc["path"].split("\/")[-1])
	end

	def is_program_language()
		execfile = @proc["path"].split("\/")[-1]
		return true if @program_language.include?(execfile)
		return true if execfile =~ /java|php|python|perl|ruby|lua|go/
		false
	end

	def get_id()
		{
		"pid"	=> @proc["pid"],
		"ppid"	=> @proc["ppid"],
		"sid"	=> @proc["spid"],
		"pgid"	=> @proc["pgid"],
		"ruid"	=> @proc["uid"],
		"suid"	=> @proc["suid"],
		"euid"	=> @proc["euid"],
		"gid"	=> @proc["gid"],
		"sgid"	=> @proc["sgid"],
		"egid"	=> @proc["egid"]

		}
	end	
	
	def is_socket()
		@proc["is_socket"] == "1" ? true : false
	end

	def start_time()
		@proc["start_time"]
	end

	def executed_command()
		@proc["path"].split("\/")[-1]
	end

	def cmdline()
		@proc["cmd"]
	end

	def comm()
		@proc["comm"].chomp
	end
	
	
	def mode()
		@proc["mode"]
	end
end


procs_hash = {}
procs.each{|pid,info|
	procs_hash[pid] = ProcCase.new(procs[pid])
}

def is_nc_shell(proc_case)
	if proc_case.executed_command =~ /nc|ncat/ and proc_case.cmdline =~ /[\s|\t]-e[\s|\t]/
		return true
	else
		return false
	end

	if proc_case.executed_command =~ /nc|ncat/ and proc_case.cmdline =~ /\|/
                return true
        else
                return false
        end
end 
#p is_nc_shell(test_proc)

def father_ppid(proc_case)
	proc_case.get_id["ppid"]
end

def father_proc(procs_hash,ppid)
	procs_hash[ppid]
end

# RULES

# 规则1.父进程为某个普通的进程，子进程为shell
def rule_1(procs_hash,proc_case)

	ppid = proc_case.get_id["ppid"]
	p_proc_case= father_proc(procs_hash,ppid)
	return false if proc_case.get_id['ppid'] == '0'
	return false if  p_proc_case.comm =~ /^init|sshd|login|su$/
	return false unless proc_case.is_socket
	if proc_case.comm =~ /^bash|ksh|ash|csh|dash|sh$/ and not p_proc_case.comm =~ /^bash|ksh|ash|csh|dash|sh$/
		return true
	else
		return false
	end

end

#
#规则2.父进程为某个守护程序或程序语言，子进程为另一种程序语言

def rule_2(procs_hash,proc_case)
        ppid = proc_case.get_id["ppid"]
        p_proc_case= father_proc(procs_hash,ppid)
	return false if proc_case.get_id['ppid'] == '0'
	return false unless proc_case.is_program_language and p_proc_case.is_program_language
	if proc_case.executed_command != p_proc_case.executed_command
		return true 
	else
		return false
	end
end


#规则3.init派生的bash、ash、ksh……等等。（PHP、ruby、perl也要监控，单python暂不考虑，python对误报和漏报的影响较大）

def rule_3(procs_hash,proc_case)
        ppid = proc_case.get_id["ppid"]
        p_proc_case= father_proc(procs_hash,ppid)
	
	return false unless proc_case.get_id['ppid'] == '1'
	return true if proc_case.comm =~ /^bash|ksh|ash|csh|dash|sh$/
	return true if ["java","php","perl","ruby","lua","go"].include? proc_case.comm.downcase
	return false
	
end


#规则4.nc shell


def rule_4(procs_hash,proc_case)
	is_nc_shell(proc_case)
end


# 5 Local Privilege Escalation

def rule_5(procs_hash,proc_case)
        ppid = proc_case.get_id["ppid"]
        p_proc_case= father_proc(procs_hash,ppid)

	return false if proc_case.get_id['ppid'] == "0" or proc_case.get_id['ppid'] == "1"

	if proc_case.get_id["euid"] == "0" and not p_proc_case.get_id["euid"] == "0"
		return false if proc_case.mode[3] = 's' or proc_case.mode[6] = 's'
#		return false if proc_case.env =~ /SUDO_COMMAN/
		return true
	else
		return false
	end
	
end
puts "##############################"
#=begin
procs_hash.each{|pid,proc_case|
	 puts "rule 1 was hitted by process #{pid}" if rule_1(procs_hash,proc_case)
	 puts "rule 2 was hitted by process #{pid}" if rule_2(procs_hash,proc_case)
	 puts "rule 3 was hitted by process #{pid}" if rule_3(procs_hash,proc_case)
	 puts "rule 4 was hitted by process #{pid}" if rule_4(procs_hash,proc_case)
	 puts "rule 5 was hitted by process #{pid}" if rule_5(procs_hash,proc_case)
}

#=end

#test_proc = ProcCase.new(procs["3552"])
#p test_proc.mode
#p rule_5(procs_hash,test_proc)

