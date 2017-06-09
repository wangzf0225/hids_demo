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
        return p,c
end

def show_your_num(hash)
	show = {}
	hash.each{|char,index|
		next if char == "TOTAL"
		show.store(char,char.ord)
	}
	show
end
s = <<EOF
<?php ${'_'.$_}['_'](${'_'.$_}['__']);?>
EOF
#s = $stdin.gets.scrub
s =  File.new("./webdir/817E17C2-386D-A4FB-DB3E-0DFC6667F982_S.jpg",'r').read.scrub.gsub(/\n|\r/,'')

p char_stat(s)
p cal_partation(s)
p show_your_num(char_stat(s))
