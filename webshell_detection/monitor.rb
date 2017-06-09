#! /usr/bin/env ruby
#
#Encoding.default_internal = "UTF-8"
class Test

end

def test()

end

# 检查文件的属主和更改（含创建）时间
#
def base_line(fileinfo)
	return true if not fileinfo["owner"] == 'momobot'
	time_of_create =  fileinfo["m_time_stamp"].to_f%86400/3600
	return true unless 2 < time_of_create and time_of_create < 16
	false
end

# 检查文件的文件名是否属于php以外的类型
#
def check_filename(filename)
	return true if filename.downcase =~ /^.*\.php$|^.*\.vue/
	return false unless filename.downcase =~ /\./
	
end

# 获取当前目录所有文件的inode号
#
def get_all_inode(dir)
	i_nums = []
	Dir.entries(dir).each{|each|
	next if  File.stat("#{dir}#{each}").directory?
		 i_nums << File.stat("#{dir}#{each}").ino
	}

	i_nums
end

#检查当前文件的inode号是否是孤立的
#
def is_isolated_inode(fileinfo)
	inos = get_all_inode(fileinfo["dir"]).sort
	#p "fileinfo inum = #{fileinfo["i_num"]}"
	b = a = 0
	i = inos.index(fileinfo["i_num"].to_i)
	# print "b->"
	b = inos[i]-inos[i-1] if inos[i-1] and not i==0 #rescue p inos[i],inos[i-1]
	# print "a->"
	a = inos[i+1]-inos[i] if inos[i+1]
	return true unless a.abs<10 or b.abs<10 rescue p "error:#{i},#{e}"
	false
end

# 检查最大单词
#
#
def find_longest_word(str)
	l = 0
	r = ''
	str.scan(/\w+/){|w| l,r = w.size,w if w.size > l}
	return r 
end

# 检查统计特征
#
#
def char_stat(str)
        ret = {}
        str = str.gsub(/\s|\t|�/,'')
        i = 0
        str.size.times {|index|
                next if str[index].ord.to_i < 32 or str[index].ord == "127"
                i += 1
                if ret[str[index]]
                        ret[str[index]] += 1
                else
                        ret.store(str[index],1)
                end
        }
        ret.store("TOTAL",i)
        return ret
end

# 找到最大量字符在全文中的比例
#
def cal_partation(str)
        p = 0
        c = ''
        stat_info = char_stat(str)
        stat_info.each{|char,size|
                next if char == "TOTAL"
                p,c = size.to_f/stat_info["TOTAL"],char if size.to_f/stat_info["TOTAL"] > p
        }
        return p
end

# 检查是否使用了危险的函数
#
def check_risky_function(fileinfo)
	text = File.new("#{fileinfo["dir"]}#{fileinfo["filename"]}",'r').read.scrub.gsub(/\n|\r/,'')
	#p text.encode("UTF-16be", :invalid=>:replace, :replace=>"?").encode('UTF-8')
	return {"type"=>1,"content"=>"文件长度小于200"} if text.size < 200

	return {"type"=>2,"content"=>$~[0]} if text =~ /eval|assert|phpinfo|\(['|"][\(\/].*[\)\/]e["|'],|display_errors|system\(.*\)|\bexec\(|\bpassthru\(|\bpopen\(|\bproc_open\(|\bshell_exec\(|\bcall_user_func|sleep\(|set_magic_quotes_runtime|shellpwd|\/dev\/tcp|phpspy|b374k/

        return {"type"=>3,"content"=>$~[0]} if text =~ /\${\$[0-9a-zA-z]+}|\$_(GET|POST|COOKIE|REQUEST|SERVER)\s*\[[^\]]+\]\s*\(|\/\*([^*]|\*[^\/])*\*\/\s*\(|include\s*\(\s*[^\.]+\.(png|jpg|gif|bmp)/

	return {"type"=>4,"content"=>"最大单词长度超过100"} if find_longest_word(text).size > 100 

	return {"type"=>5,"content"=>"单个字符占比超过30%(#{cal_partation(text)})"} if cal_partation(text)> 0.3

	return {"type"=>6,"content"=>"可能变形的preg_replace函数"} if text =~ /preg_replace/ and not text =~ /preg_replace\(["|']\/.*\/[imsxuADSUXJ]*?["|']/

	return false
end



#--main()--
#
# 判断是否安装了inotify-tool工具
#
is_installed_inotifytools = `rpm -qa|grep inotify-tools`

if is_installed_inotifytools == ''
	puts "Please install inotify-tools first.Run \"sudo yum install inotify-tools\"."
	exit
end

#设置被监控的目录
#
ARGV[0] ? webdir = ARGV[0] : webdir = './webdir'


#puts `inotifywait -e create,delete,modify,move -mrq #{webdir} > i&`

process = IO.popen("inotifywait -e create,delete,modify,move -mrqc #{webdir} ","r")  
while !process.eof?
	
		log = process.gets.chomp.split(",") 
		dir = log[0]
	 	event = log[1]
		file = log[2]
		if event == "CREATE" or event == "MODIFY" or event == "MOVED_TO"
			# puts file
			fileinfo = {}
			next if file =~ /php\.swx/
			stat_info = `stat -c "%U|%Y|%y|%i|%a" "#{dir}#{file.gsub("$",'\$').gsub('"','\"')}"`
			fileinfo["owner"],fileinfo["m_time_stamp"],fileinfo["m_time"],fileinfo["i_num"],fileinfo["access_priv"] = stat_info.chomp.split("\|")
			fileinfo["filename"] 	= file
			fileinfo["dir"]		= dir
			print "文件信息："
			p fileinfo
			# puts "非法的文件属主或创建时间" if base_line(fileinfo)
			puts "孤立的inode编号" if is_isolated_inode(fileinfo)
			p keyword_check = check_risky_function(fileinfo)
			if keyword_check 
				type = ['',
					"文件长度异常",
					"恶意关键字",	
					"恶意关键字",	
					"单词长度异常",
					"单个字符比例异常"
					]
				puts "#{type[keyword_check["type"]]}-->#{keyword_check["content"]}"
			end
			#print "owner:#{owner},acc_priv:#{access_priv}"
		end
	
end


