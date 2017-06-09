#! /usr/bin/env ruby
#
require 'json'

def is_promisc()
	mode = `ip link|grep PROMISC`
	mode =~ /PROMISC/?true:false	
end
#p is_promisc()


def get_tcp_data()
	tcp_con = File.new("/proc/net/tcp").read.split("\n")[1..-1].map{|line|
		v = line.split
		h = {
			"sl"		=> v[0],
			"local_address"	=> v[1], 
			"rem_address"	=> v[2], 
			"st" 		=> v[3], 	
			"tx_queue"   	=> v[4].split(":")[0], 
			"rx_queue"   	=> v[4].split(":")[1], 
			"tr"   		=> v[5].split(":")[0], 
			"tm->when"   	=> v[5].split(":")[1], 
			"retrnsmt"   	=> v[6], 
			"uid"   	=> v[7], 
			"timeout"   	=> v[8], 
			"inode"   	=> v[9],		
			}
	}
end

#puts get_tcp_data()

def get_udp_data()
	udp_con = File.new("/proc/net/udp").read.split("\n")[1..-1].map{|line|
		v = line.split
		h = {
			"sl"		=> v[0],
			"local_address"	=> v[1], 
			"rem_address"	=> v[2], 
			"st" 		=> v[3], 	
			"tx_queue"   	=> v[4].split(":")[0], 
			"rx_queue"   	=> v[4].split(":")[1], 
			"tr"   		=> v[5].split(":")[0], 
			"tm->when"   	=> v[5].split(":")[1], 
			"retrnsmt"   	=> v[6], 
			"uid"   	=> v[7], 
			"timeout"   	=> v[8], 
			"inode"   	=> v[9],		
			"ref"		=> v[10],
			"pointer"	=> v[11],
			"drops"		=> v[12]	
			}
	}
end

#puts get_udp_data

def ip_convert_hex_to_bin(hex)
	ip_hex = []
	 #hex[6..7]+hex[4..5]+hex[2..3]+hex[0..1] 

	ip_hex << "%08b" % "0x#{hex[6..7]}"
	ip_hex << "%08b" % "0x#{hex[4..5]}"
	ip_hex << "%08b" % "0x#{hex[2..3]}"
	ip_hex << "%08b" % "0x#{hex[0..1]}"
	ip_hex.join
end

def is_intern_addr(addr)
	return true if addr =~ /^00001010|^101011000001|^1100000010101000/
	false
end

 
def is_access_internet(conn_data)
	conn_data.each{|each|
		puts "Connection #{each["sl"]} is accessing internet" unless is_intern_addr(ip_convert_hex_to_bin(each["local_address"])) and is_intern_addr(ip_convert_hex_to_bin(each["rem_address"]))
	}
end


#--main--

tcp_data = get_tcp_data()

udp_data = get_udp_data()

puts "\n<--Sniffer check-->"
if is_promisc()
	puts "本主机网卡被设置为混杂模式，可能被利用进行sniff。"
else
	puts "网卡PROMISC模式正常。"
end

puts "\n<--TCP Connection-->"
is_access_internet(tcp_data)

puts "\n<---UDP Connection->"
is_access_internet(udp_data)
