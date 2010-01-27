#!/usr/bin/env ruby

# Fox/GUI program designed to alter small to "reasonably sized" packet
# captures.  Enhancements should continue to provide fodder for stress testing
# of traffic inspection/reassembly programs.

# Copyright notice:
#  (C) 2010
# This software is provided 'as-is' without any express or implied warranty.
# In no event will the authors be held liable for damages arising from the
# use of this software.  All license is reserved.

require 'rubygems' rescue nil
require 'fox16'

include Fox

# Class that defines an individual packet (frame would be a more precise
# term).  Translations on this packet are performed as methods within this
# class.
class Packet

  # Net to Ruby Long - Convert a network-byte-order string into a Fixnum
  def ntorl(str)
    num = 0
    str.reverse.each_byte { |x| num = (num << 8) + x }
res = '' ; str.reverse.each_byte { |x| res << ("%02x" % x) } ; puts "Converting '#{res}' to #{num} (#{res.to_i(16)})"
    return num
  end

  # If src is a File object, read one frame from it.
  # last_time contains the timestamp of the previous frame as a float.
  def initialize(src, last_time)
    @time_offset = 0.0       # seconds since previous frame
    @content = nil           # nested collection of headers and data
    @orig_len = 0            # original length of original packet

    # Handle reading one frame from a file
    if src.class <= File
      # Get the header of this frame
      frame_hdr = src.read(16)
      abs_time = ntorl(frame_hdr[0,4]) + ntorl(frame_hdr[4,4]).to_f / 1000000
puts abs_time
      @time_offset = abs_time - last_time
      @orig_len = ntorl(frame_hdr[12,4])
      cap_len = ntorl(frame_hdr[8,4])
puts "payload length: #{cap_len}"

      # Now get the payload of this frame
      payload = src.read(cap_len)
      @content = payload
    end
  end

  attr_reader :time_offset, :orig_len, :content

  # A little awkward - if this is the first packet of the cpature, it has
  # a huge time_offset (the full timestamp).  So as a hack, reset the ts_sec
  # portion of its offset, and return that as the timestamp in seconds.
  def get_init_time
    seconds = @time_offset.to_i
    @time_offset -= seconds
    return seconds
  end

end  # of class Packet



pcap = File.open ARGV[0]
hdr = pcap.read(24)
packets = []
timestamp = 0.0
while pcap.pos < pcap.lstat.size - 15 do
  packets << Packet.new(pcap, timestamp)
  timestamp += packets.last.time_offset
end
puts packets.length
