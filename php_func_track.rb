#! /usr/bin/env ruby
#
require 'thread'
process = IO.popen("phptrace -p all ","r"){|io|
  if io
    # parent
    # io.gets
  else
    # child
    s = gets
    puts "child output: " + s
  end
}
exit
p process.methods
#process = IO.popen("echo 23434","r")
while !process.eof?

#       p 123
        p process.gets
end


