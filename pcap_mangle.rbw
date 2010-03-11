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
require 'ipaddr'
require 'md5'
require 'set'

include Fox


# Module for endian/integer conversions
module EndianMess

  # Host to Ruby Long - Convert a host-byte-order string into a Fixnum
  def htorl(str)
    num = 0
    str.reverse.each_byte { |x| num = (num << 8) + x }
    return num
  end

  # Net to Ruby Long - Convert a network-byte-order string into a Fixnum
  def ntorl(str)
    num = 0
    str.each_byte { |x| num = (num << 8) + x }
    return num
  end

  # Ruby Long to Host - Convert a Fixnum to a 4-byte host-byte-order string
  def rltoh(num)
    str = ''
    4.times do
      str << (num & 0xFF).chr
      num >>= 8
    end
    str
  end

  # Ruby Long to Net - Convert a Fixnum to a 4-byte network-byte-order string
  def rlton(num)
    rltoh(num).reverse
  end

end  # of module EndianMess

# Top-level class that assists with recursively examining packets and
# their contained headers
class NestedPacket
  include EndianMess

  attr_reader :content, :hdr
  attr_writer :content, :hdr

  # Recurses until @content is merely a String.  Grabs current-level content
  # until then by calling the details() method.
  def inspect
    proto = self.class.to_s.sub('Packet', '')
    unless proto.empty?
      hdr = details()
      if not hdr
        proto = ''
      elsif hdr.empty?
        proto = "[#{proto}]  "
      else
        proto = "[#{proto} #{details()}]  "
      end
    end
    
    # Recurse to the next level when appropriate
    next_inspect = ''
    if @content.class <= String
      if @content.length > 0
        next_inspect = "[Data #{@content.length}]"
      else
        next_inspect = ''
      end
    else
      next_inspect = @content.inspect()
    end
    "#{proto}#{next_inspect}"
  end

  # The checksum better have been recomputed already when this is called
  # for TCP and UDP and IP.
  def to_s
    @hdr + @content.to_s
  end

  # If we're a packet class that doesn't offer checksumming, just forward
  # the request deeper within our nest.  Maybe somebody wants it!
  def checksum!
    @content.checksum! unless @content.class <= String
  end

  # Nested packets that retain @hdr + @content and nothing else can simply
  # use this function to recursively calculate length
  def length
    @hdr.length + @content.length
  end

  # Pass fragmentation requests down until we hit an appropriate level 3
  # protocol.  On the way back up, if fragmentation has occurred then an
  # array will be returned.  Prepend our header to each element and return.
  def fragment!(frag_options)
    return nil if @error or @content.class <= String
    frags = @content.fragment!(frag_options)
    if frags
      frags.collect! do |x|
        frag = self.dup
        frag.unique!
        frag.content = x
        frag
      end
    end
    return frags
  end

  # Pass segmentation demands down until we hit an appropriate level 4
  # protocol.  On the way back up, if segmentation has occurred then an array
  # will be returned.  Prepend our header to each element and return.
  def segment!
    return nil if @error or @content.class <= String
    segs = @content.segment!
    if segs
      segs.collect! do |x|
        seg = self.dup
        seg.unique!
        seg.content = x
        seg
      end
    end
    return segs
  end

  # We don't want to share any metadata, so let's grab our own copy
  def unique!
    @hdr = @hdr.dup if @hdr
    @error = @error.dup if @error
  end

  # Pass on mangling requests to deeper levels
  def mangle_ip!(salt)
    return nil if @error or @content.class <= String
    @content.mangle_ip!(salt)
  end
  def mangle_port!(salt)
    return nil if @error or @content.class <= String
    @content.mangle_port!(salt)
  end
  def vlan_tag!(vlan_id)
    return nil if @error or @content.class <= String
    @content.vlan_tag!(vlan_id)
  end
  def add_options!
    return nil if @error or @content.class <= String
    @content.add_options!
  end    

  # The persistence of this method is handled in the next-lower layer.  Eg,
  # Ethernet handles IP's persistence.  This can be any layer, however, that
  # can contain an IP header directly within it.  VLAN and GRE can also.
  # Any such layer must define the set_ethertype() header.
  def ip_426!
    return nil if @error or @content.class <= String
    ret = @content.ip_426!
    if ret
      @content = ret
      set_ethertype("\x86\xDD")
    end
    return nil
  end    

  # Pass on flow identification requests to deeper levels
  def flow_id
    return '' if @error or @content.class <= String
    return self.class.to_s + @content.flow_id
  end

  # Pass on TCP state requests to deeper levels, appending headers in
  # descending order.
  def tcp_rst
    return nil if @error or @content.class <= String
    rst = @content.tcp_rst
    rst << @hdr if rst
    return rst
  end

  # Insert GRE encapsulation in the first layer-2 header
  def gre_tunnel!(ip_hdr)
    return '' if @error or @content.class <= String
    @content.gre_tunnel!(ip_hdr)
  end

end  # of class NestedPacket


######  Packet Headers in Descending Order  ######

# Class that holds TCP packets
class TCPPacket < NestedPacket

  def initialize(data, fragmented = false)
    @error = nil
    @hdr = ''
    if fragmented
      @error = "Fragment"
      @content = data
      return nil
    end
    
    # Validate the length of the header
    hdr_len = (data[12].to_i >> 4) * 4
    if data.length < hdr_len or hdr_len < 20
      @error = "Truncated"
      @content = data
      return nil
    end

    # Grab our header.  Next layer is always content for TCP.
    @hdr = data[0,hdr_len]
    data[0,hdr_len] = ''
    @content = data
  end

  def details()
    return @error if @error
    src = (@hdr[0] << 8) + @hdr[1]
    dst = (@hdr[2] << 8) + @hdr[3]
    opts = ''
    opts = 'Opts ' if @hdr.length > 20
    opts + "#{src} > #{dst}"
  end

  # Recalculate the checksum field for this TCP packet.  Thanks to the
  # TCP pseudo-header, the 8 bytes of the IP header containing source and
  # destination address need to be provided.  *sigh*  Layering violations.
  def checksum!(ip_bytes = nil)
    return nil if @error or not ip_bytes
    @content.checksum! unless @content.class <= String

    # Gather all the data on which we'll be calculating our checksum
    data = @hdr + @content.to_s
    data[16,2] = "\x00\x00"  # zero the checksum initially
    len = data.length
    data << "\x00" if len & 1 == 1
    data << ((len >> 8).chr + (len & 0xFF).chr)
    data << ip_bytes

    # Start calculating the checksum, 2 bytes at a time, starting with 6
    checksum = 6    # TCP protocol
    pos = 0
    while pos < data.length do
      checksum += (data[pos] << 8) + data[pos+1];
      if checksum > 0xFFFF
        checksum += 1
        checksum &= 0xFFFF
      end
      pos += 2
    end
    checksum = checksum ^ 0xFFFF
    @hdr[16] = (checksum >> 8)
    @hdr[17] = (checksum & 0xFF)
  end

  # Contribute our piece to unique flow identification
  def flow_id
    return 'TCP' if @error
    return (@hdr[0] + @hdr[2]).to_s + (@hdr[1] * @hdr[3]).to_s(16)
  end

  # Deterministically "randomize" the source and destination ports
  def mangle_port!(salt)
    return nil if @error
    @hdr[0,2] = MD5::digest(@hdr[0,2] + salt)[0,2]
    @hdr[2,2] = MD5::digest(@hdr[2,2] + salt)[0,2]
  end

  # Add an option field to this packet.
  def add_options!
    return nil if @error
    @content.add_options! unless @content.class <= String
    return nil if @hdr.length != 20   # already have options

    # Add four padding bytes as options
    @hdr << "\x02\x04\x05\xb4\x01\x01\x04\x02"
    @hdr[12] = (@hdr.length << 2)
  end

  # If this packet has a payload, segment into a swarm of one-byte chunks.
  def segment!
    return nil if @content.length < 2 or @error
    payload = @content.to_s
    seq = ntorl(@hdr[4,4])
    segments = []
    payload.length.times do |i|
      synth = @hdr.dup
      synth[4,4] = rlton(seq)
      seq = (seq + 1) & 0xFFFFFFFF
      segments << TCPPacket.new(synth + payload[i,1])
    end
    return segments
  end

  # Return a copy of our header, already adjusted for injection.
  def tcp_rst
    hdr = @hdr[0,20]
    hdr[4,4] = rlton(ntorl(@hdr[4,4]) + @content.length)
    hdr[12,2] = "\x50\x14"  # 20 byte packet, RST + ACK flags set
    [ hdr ]
  end

end  # of class TCPPacket


# Class that holds UDP packets
class UDPPacket < NestedPacket

  def initialize(data, fragmented = false)
    @error = nil
    @hdr = ''
    if fragmented
      @error = "Fragment"
      @content = data
      return nil
    end

    # Validate the header's presence
    hdr_len = 8
    if data.length < hdr_len
      @error = "Truncated"
      @content = data
      return nil
    end

    # Grab our header.  Next layer is always content for UDP.
    @hdr = data[0,hdr_len]
    data[0,hdr_len] = ''
    @content = data
  end

  def details()
    return @error if @error
    src = (@hdr[0] << 8) + @hdr[1]
    dst = (@hdr[2] << 8) + @hdr[3]
    "#{src} > #{dst}"
  end

  # Right now checksum just gets zeroed, which is fine for UDP
  def checksum!(ip_bytes = nil)
    return nil if @error
    @content.checksum! unless @content.class <= String
    @hdr[6,2] = "\x00\x00"
  end

  # Contribute our piece to unique flow identification
  def flow_id
    return (@hdr[0] ^ @hdr[2]).to_s + (@hdr[1] + @hdr[3]).to_s(16)
  end

  # Deterministically "randomize" the source and destination ports
  def mangle_port!
    return nil if @error
    @hdr[0,2] = MD5::digest(@hdr[0,2] + salt)[0,2]
    @hdr[2,2] = MD5::digest(@hdr[2,2] + salt)[0,2]
  end

end  # of class UDPPacket


# Class that holds the 64-bit IPv6 Fragment Header
class IPv6FragmentPacket < NestedPacket
  
  def initialize(data)
    @error = nil
    @hdr = ''
    hdr_len = 8
    if data.length < hdr_len
      @error = "Truncated"
      @content = data
      return nil
    end

    # Grab our header
    @hdr = data[0,hdr_len]
    data[0,hdr_len] = ''
    next_layer = @hdr[0]

    # Examine the protocol field for types we recognize
    if next_layer == 6
      @content = TCPPacket.new(data, true)
    elsif next_layer == 17
      @content = UDPPacket.new(data, true)
    else
      @content = data
    end
  end

  def details()
    return @error if @error
    ''
  end  

end  # of IPv6FragmentPacket class


# Class that holds IPv6 packets
class IPv6Packet < NestedPacket

  def initialize(data)
    @error = nil
    @hdr = ''
    hdr_len = 40
    if data.length < hdr_len
      @error = "Truncated"
      @content = data
      return nil
    end
    #payload_length = (data[4] << 8) + data[5]

    # Grab our header
    @hdr = data[0,hdr_len]
    data[0,hdr_len] = ''
    next_layer = @hdr[6]
    
    # Examine the protocol field for types we recognize
    if next_layer == 6
      @content = TCPPacket.new(data, false)
    elsif next_layer == 17
      @content = UDPPacket.new(data, false)
    elsif next_layer == 44
      @content = IPv6FragmentPacket.new(data)
    elsif next_layer == 47
      @content = GREPacket.new(data)
    else
      @content = data
    end
  end

  # Take a 16-byte string and convert it to a Ruby IPAddr object
  def ipv6_addr(bytes)
    num = 0
    bytes.each_byte { |x| num = (num << 8) + x }
    IPAddr.new(num, Socket::AF_INET6)
  end

  def details()
    return @error if @error
    src = ipv6_addr(@hdr[8,16])
    dst = ipv6_addr(@hdr[24,16])
    "#{src} > #{dst}"
  end

  # Checksumming is easy because there is no network layer checksum in IPv6!
  # Just pass the bytes necessary for pseudo-header computation if needed.
  def checksum!
    return nil if @error
    if @content.class <= TCPPacket or @content.class <= UDPPacket
      @content.checksum!(@hdr[8,32])
    else
      @content.checksum! unless @content.class <= String
    end
  end

  # Contribute our piece to unique flow identification
  def flow_id
    return 'IPv6' if @error
    next_hdr = ''
    next_hdr = @content.flow_id unless @content.class <= String
    this_hdr = ipv6_addr(@hdr[8,16]).to_i + ipv6_addr(@hdr[24,16]).to_i
    return this_hdr.to_s(16) + next_hdr
  end

  # Deterministically "randomize" the source and destination IP addresses
  def mangle_ip!(salt)
    return nil if @error
    if (salt == :template)
      if @hdr[8,16] > @hdr[24,16]
        hdr[8,16]  = "\xab\xcd\0\0\0\0\0\0\0\0\0\0\0\0\0\x02"
        hdr[24,16] = "\xab\xcd\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"
      else
        hdr[8,16]  = "\xab\xcd\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"
        hdr[24,16] = "\xab\xcd\0\0\0\0\0\0\0\0\0\0\0\0\0\x02"
      end
    else
      @hdr[8,16] = MD5::digest(@hdr[8,16] + salt)
      @hdr[24,16] = MD5::digest(@hdr[24,16] + salt)
      @hdr[10,10] = "\0" * 10
      @hdr[26,10] = "\0" * 10
    end
    checksum!
  end

  # TCP or UDP above us wants mangled ports, but we're responsible for
  # checksumming.
  def mangle_port!(salt)
    return nil unless @content.class == TCPPacket or
                      @content.class == UDPPacket
    @content.mangle_port!(salt)
    checksum!
  end

  # IPv6 fragments contain an optional extension header, otherwise the IPv6
  # header remains relatively unchanged.
  def fragment!(frag_options)
    return nil if @error

    # If it's too short or already fragmented then don't fragment.  Also, for
    # now let's only fragment TCP and UDP packets
    return nil if @content.length < 11

    # Fragment based on requested fragmentation type
    payload = @content.to_s
    chunks = []
    if frag_options.type == :random and frag_options.fragments > 1
      pos = 0

      # Split the payload into 8-byte chunks
      while pos < payload.length do
        chunks << payload[pos, 8]
        pos += 8
      end

      # Now merge the 8-byte chunks randomly until we have few enough
      while chunks.length > frag_options.fragments
        i = rand(chunks.length - 1)
        chunks[i, 2] = [ chunks[i,2].join ]
      end
    elsif frag_options.type == :mtu
      avail = (frag_options.bytes - 14 - @hdr.length) / 8 * 8
      return nil if avail >= payload.length or avail < 8
      
      # Now split the payload into avail-sized chunks
      pos = 0
      while pos < payload.length do
        chunks << payload[pos, avail]
        pos += avail
      end
    end  # of fragmentation type
    return nil if chunks.empty?

    # Now let's generate an array of IPv6 packets with the same header as this
    # one, with the appropriate fragment metadate set in the optional header
    pos = 0
    mf = 0x01
    id = rand(256).chr + rand(256).chr + rand(256).chr + rand(256).chr
    chunk_num = 0
    chunks.collect do |chunk|
      frag = @hdr.dup
      frag_hdr = @hdr[6,1] + "\0AA" + id
      chunk_num += 1
      mf = 0 if chunk_num == chunks.length
      frag_hdr[2] = (pos >> 8) & 0xFF              # fragment offset, in 8-byte
      frag_hdr[3] = (pos & 0xF8) + mf              # chunks, plus MF byte
      frag[5] = (chunk.length + 8) & 0xFF          # payload length, top byte
      frag[4] = ((chunk.length + 8) >> 8) & 0xFF   # ...bottom byte
      frag[6] = 44                                 # next-hop = fragment header
      pos += chunk.length
      IPv6Packet.new(frag + frag_hdr + chunk)
    end
  end

  # If the next layer is TCP, let's fragment it and then re-checksum.
  # Remember: the IPv6 header denotes the length of the TCP payload
  def segment!
    return nil if @error or @content.class <= String
    segs = @content.segment!
    if segs
      segs.collect! do |x|
        seg = self.dup
        seg.unique!
        seg.content = x
        seg.hdr[4,2] = rlton(x.length)[2,2]
        seg.checksum!
        seg
      end
    end
    return segs    
  end

  # Pass on TCP state requests to the next level.  If it returns an array,
  # add an appropriate IP header for RST injection.
  def tcp_rst
    return nil if @error or @content.class <= String
    rst = @content.tcp_rst
    if rst
      if rst.length == 1   # TCP is next layer
        hdr = "\x06\x00\x00\x00\x00\x14\x06\x40" + @hdr[8,32]
        rst << hdr
      else
        rst << @hdr.dup
      end
    end
    rst
  end

end  # of class IPv6Packet


# Class that holds IPv4 packets
class IPPacket < NestedPacket

  def initialize(data)
    @error = nil
    @hdr = ''
    hdr_len = (data[0].to_i - 0x40) * 4
    total_length = (data[2].to_i << 8) + data[3].to_i
    if data.length < hdr_len or hdr_len < 20 or total_length > data.length
      @error = "Truncated"
      @content = data
      return nil
    end

    # Grab our header
    data[total_length..-1] = ''
    @hdr = data[0,hdr_len]
    data[0,hdr_len] = ''
    next_layer = @hdr[9]
    fragmented = (@hdr[6] & 0x3F) + @hdr[7] > 0

    # Examine the protocol field for types we recognize
    if next_layer == 6
      @content = TCPPacket.new(data, fragmented)
    elsif next_layer == 17
      @content = UDPPacket.new(data, fragmented)
    elsif next_layer == 47
      @content = GREPacket.new(data)
    else
      @content = data
    end
  end

  def details()
    return @error if @error
    src = IPAddr.new(ntorl(@hdr[12,4]), Socket::AF_INET)
    dst = IPAddr.new(ntorl(@hdr[16,4]), Socket::AF_INET)
    opts = ''
    opts = 'Opts ' if @hdr.length > 20
    opts + "#{src} > #{dst}"
  end

  def checksum!
    return nil if @error
    @hdr[10,2] = "\x00\x00"  # zero the checksum initially

    # If this packet contains TCP or UDP, tell it to checksum as well!
    # And because we're nice, give it information it needs for pseudo-header.
    if @content.class <= TCPPacket or @content.class <= UDPPacket
      @content.checksum!(@hdr[12,8])
    else
      @content.checksum! unless @content.class <= String
    end

    # Calculate the IP checksum
    checksum = 0
    pos = 0
    while pos < @hdr.length do
      checksum += (@hdr[pos] << 8) + @hdr[pos+1];
      if checksum > 0xFFFF
        checksum += 1
        checksum &= 0xFFFF
      end
      pos += 2
    end
    checksum = checksum ^ 0xFFFF
    @hdr[10] = (checksum >> 8)
    @hdr[11] = (checksum & 0xFF)
  end

  # We have been instructed to fragment!  This should be fun.  If it's by
  # MTU, try our best to fit within it.  Otherwise, fragment as much as
  # possible and then randomly merge until we're within our limits.  Return
  # nil if no fragmentation occurs.
  def fragment!(frag_options)
    return nil if @error

    # If it's too short or already fragmented then don't fragment.
    # And ignore the goddamn Don't Fragment bit.
    return nil if (@hdr[6] & 0xBF) + @hdr[7] > 0
    return nil if @content.length < 11

    # Fragment based on requested fragmentation type
    payload = @content.to_s
    chunks = []
    if frag_options.type == :random and frag_options.fragments > 1
      pos = 0

      # Split the payload into 8-byte chunks
      while pos < payload.length do
        chunks << payload[pos, 8]
        pos += 8
      end

      # Now merge the 8-byte chunks randomly until we have few enough
      while chunks.length > frag_options.fragments
        i = rand(chunks.length - 1)
        chunks[i, 2] = [ chunks[i,2].join ]
      end
    elsif frag_options.type == :mtu
      avail = (frag_options.bytes - 14 - @hdr.length) / 8 * 8
      return nil if avail >= payload.length or avail < 8
      
      # Now split the payload into avail-sized chunks
      pos = 0
      while pos < payload.length do
        chunks << payload[pos, avail]
        pos += avail
      end
    end  # of fragmentation type
    return nil if chunks.empty?

    # Now let's generate an array of IP packets with the same header as this
    # one, but with the appropriate fragment metadate set in the header
    pos = 0
    mf = 0x20
    chunk_num = 0
    chunks.collect do |chunk|
      frag = @hdr.dup
      total = frag.length + chunk.length
      chunk_num += 1
      mf = 0 if chunk_num == chunks.length
      frag[7] = pos & 0xFF
      frag[6] = ((pos >> 8) & 0x1F) + mf
      frag[3] = total & 0xFF
      frag[2] = (total >> 8) & 0xFF
      pos += (chunk.length / 8)
      frag = IPPacket.new(frag + chunk)
      frag.checksum!
      frag
    end
  end

  # If the next layer is TCP, let's fragment it and then re-checksum.
  # Remember: the IP header denotes the length of the TCP payload
  # NOTE:  For fragmentation support we need to randomize the packet ID
  def segment!
    return nil if @error or @content.class <= String
    segs = @content.segment!
    if segs
      segs.collect! do |x|
        seg = self.dup
        seg.unique!
        seg.content = x
        seg.hdr[2,2] = rlton(seg.hdr.length + x.length)[2,2]
        seg.hdr[4,2] = rand(256).chr + rand(256).chr
        seg.checksum!
       seg
      end
    end
    return segs    
  end

  # Contribute our piece to unique flow identification
  def flow_id
    return 'IPv4' if @error
    next_hdr = ''
    next_hdr = @content.flow_id unless @content.class <= String
    return (@hdr[12] + @hdr[16]).to_s + (@hdr[13] ^ @hdr[17]).to_s(16) +
           (@hdr[14] + @hdr[18]).to_s + (@hdr[15] ^ @hdr[19]).to_s(16) +
           next_hdr
  end

  # Deterministically "randomize" the source and destination IP addresses
  def mangle_ip!(salt)
    return nil if @error
    if (salt == :template)
      if @hdr[12,4] > @hdr[16,4]
        @hdr[12,4] = "\x0a\0\0\x02"
        @hdr[16,4] = "\x0a\0\0\x01"
      else
        @hdr[12,4] = "\x0a\0\0\x01"
        @hdr[16,4] = "\x0a\0\0\x02"
      end
    else
      @hdr[12,4] = MD5::digest(@hdr[12,4] + salt)[0,4]
      @hdr[16,4] = MD5::digest(@hdr[16,4] + salt)[0,4]
    end
    checksum!
  end

  # TCP or UDP above us wants mangled ports, but we're responsible for
  # checksumming.
  def mangle_port!(salt)
    return nil if @error or (@hdr[6] & 0xBF) + @hdr[7] > 0 or
                  (@content.class != TCPPacket and @content.class != UDPPacket)
    @content.mangle_port!(salt)
    checksum!
  end

  # Magically convert ourselves into an IPv6 packet!
  def ip_426!
    return nil if @error or (@hdr[6] & 0xBF) + @hdr[7] > 0
    payload_length = @content.length
    fake_hdr = "\x06\0\0\0" + (payload_length >> 8).chr +
               (payload_length & 0xFF).chr + @hdr[9,1] + "\x40"
    src = "\x1b\xff" + ("\0" * 10) + @hdr[12,4]
    dst = "\x1b\xff" + ("\0" * 10) + @hdr[16,4]
    new_packet = IPv6Packet.new(fake_hdr + src + dst + @content.to_s)
    new_packet.checksum!
    return new_packet
  end

  # Add an option field to this packet.
  def add_options!
    return nil if @error
    @content.add_options! unless @content.class <= String
    return nil if @hdr.length != 20   # already have options

    # Let's add a "timestamp" option field
    @hdr << "\x44\x10\x10\x00"  # type (timestamp), length (16), offset (16)
                                # overflow + flags (unset)
    @hdr << "\x01\x02\x03\x04"  # internet ID
    8.times { @hdr << rand(256).chr }  # random timestamp information
    
    # Now adjust our header length and total length
    total_length = @hdr.length + @content.length
    @hdr[0] = 0x40 + (@hdr.length >> 2)
    @hdr[2] = (total_length >> 8) & 0xFF
    @hdr[3] = total_length & 0xFF
  end

  # Pass on TCP state requests to the next level.  If it returns an array,
  # add an appropriate IP header for RST injection.
  def tcp_rst
    return nil if @error or @content.class <= String
    rst = @content.tcp_rst
    if rst
      if rst.length == 1   # TCP is next layer
        hdr = "\x45\x00\x00\x28\x1e\xe7\x00\x00\x80\x06\xFF\xFF" +
              @hdr[12,8]
        rst << hdr
      else
        rst << @hdr.dup
      end
    end
    rst
  end

end  # of class IPPacket


# Holds GRE header
class GREPacket < NestedPacket

  def initialize(data)
    @error = nil
    @hdr = ''
    if data.length < 4
      @error = "Truncated"
      @content = data
      return nil
    end
    if data[0] & 0x40 > 0
      @error = "SRE!"
      @content = data
      return nil
    end

    # Figure out how big the header is
    hdr_len = 4
    hdr_len += 4 if (data[0] & 0xb0) > 0
    hdr_len += 4 if (data[0] & 0x20) > 0
    hdr_len += 4 if (data[0] & 0x10) > 0

    # Grab our header
    @hdr = data[0,hdr_len]
    data[0,hdr_len] = ''
    next_layer = @hdr[2,2]
 
    # Examine the Ethernet Type field for types we recognize
    if next_layer == "\x08\x00"
      @content = IPPacket.new(data)
    elsif next_layer == "\x86\xDD"
      @content = IPv6Packet.new(data)
    elsif next_layer == "\x81\x00" or next_layer == "\x91\x00"
      @content = VLANPacket.new(data)
    else
      # We don't recognize this type.  Oh well.
      @content = data
    end
  end
  
  def details()
    return @error if @error
    return ''
  end

  # We have been instructed to change our ethertype
  def set_ethertype(new_type)
    raise "Bad ethertype: #{new_type.inspect}" unless new_type.length == 2
    @hdr[2,2] = new_type
  end

end  # of class GREPacket


# Holds inner and outer VLAN headers
class VLANPacket < NestedPacket
  
  def initialize(data)
    @error = nil
    @hdr = ''
    if data.length < 4
      @error = "Truncated"
      @content = data
      return nil
    end

    # Grab our header
    @hdr = data[0,4]
    data[0,4] = ''
    next_layer = @hdr[2,2]
 
    # Examine the Ethernet Type field for types we recognize
    if next_layer == "\x08\x00"
      @content = IPPacket.new(data)
    elsif next_layer == "\x86\xDD"
      @content = IPv6Packet.new(data)
    elsif next_layer == "\x81\x00" or next_layer == "\x91\x00"
      @content = VLANPacket.new(data)
    else
      # We don't recognize this type.  Oh well.
      @content = data.dup
    end
  end

  def details()
    return @error if @error
    return ''
  end

  # We have been instructed to change our ethertype
  def set_ethertype(new_type)
    raise "Bad ethertype: #{new_type.inspect}" unless new_type.length == 2
    @hdr[2,2] = new_type
  end

end  # of class VLANPacket


# Class that holds Ethernet packets.  Pretty simple, really.
class EthernetPacket < NestedPacket

  # Pull off our own data, then construct interior headers we recognize
  def initialize(data)
    @error = nil
    @hdr = ''
    if data.length < 14
      @error = "Truncated"
      @content = data
      return nil
    end

    # Grab our header
    @hdr = data[0,14]
    data[0,14] = ''
    next_layer = @hdr[12,2]
 
    # Examine the Ethernet Type field for types we recognize
    if next_layer == "\x08\x00"
      @content = IPPacket.new(data)
    elsif next_layer == "\x86\xDD"
      @content = IPv6Packet.new(data)
    elsif next_layer == "\x81\x00" or next_layer == "\x91\x00"
      @content = VLANPacket.new(data)
    else
      # We don't recognize this type.  Oh well.
      @content = data
    end
  end

  def details()
    return @error if @error
    return "%02x%02x" % [@hdr[12], @hdr[13]] if @content.class <= String
    return ''
  end

  # We have been instructed to change our ethertype
  def set_ethertype(new_type)
    raise "Bad ethertype: #{new_type.inspect}" unless new_type.length == 2
    @hdr[12,2] = new_type
  end

  # Put a VLAN tag in between us and the next layer
  def vlan_tag!(vlan_id)
    return nil if @error or @content.class <= String
    vlan_hdr = vlan_id + @hdr[12,2]
    if @content.class <= VLANPacket
      set_ethertype("\x91\x00")
    else
      set_ethertype("\x81\x00")
    end
    @content = VLANPacket.new(vlan_hdr + @content.to_s)
  end

  # Put GRE encapsulation between us and the next layer
  def gre_tunnel!(ip_hdr)
    return nil if @error or @content.class <= String
    gre = ip_hdr + "\x00\x00" + @hdr[12,2] + @content.to_s

    # Set the Total Length and the Identification fields
    gre[2] = (gre.length >> 8) & 0xFF
    gre[3] = gre.length & 0xFF
    gre[4] = rand(256).chr
    gre[5] = rand(256).chr
    
    # Set our new ethertype to IP
    set_ethertype("\x08\x00") 

    # Create our encapsulated payload
    @content = IPPacket.new(gre)
    @content.checksum!
  end

end  # of class EthernetPacket


# Class that defines an individual packet (frame would be a more precise
# term).  Translations on this packet are performed as methods within this
# class.
class Packet < NestedPacket

  # If src is a File object, read one frame from it.
  # last_time contains the timestamp of the previous frame as a float.
  def initialize(src, last_time)
    @time_offset = 0.0       # seconds since previous frame
    @content = nil           # nested collection of headers and data
    @orig_len = 0            # original length of original packet
    @error = nil
    @hdr = nil

    # Handle reading one frame from a file
    if src.class <= File
      # Get the header of this frame
      frame_hdr = src.read(16)
      abs_time = htorl(frame_hdr[0,4]) + htorl(frame_hdr[4,4]).to_f / 1000000
      @time_offset = abs_time - last_time
      @orig_len = htorl(frame_hdr[12,4])
      cap_len = htorl(frame_hdr[8,4])

      # Now get the payload of this frame
      payload = src.read(cap_len)
      @content = EthernetPacket.new(payload)

    # Or read from a string directly
    elsif src.class <= String
      @content = EthernetPacket.new(src)
      @time_offset = 0.0
      @orig_len = src.length

    # Or copy ourselves from another Packet instance...
    elsif src.class == Packet
      @time_offset = src.time_offset
      @orig_len = src.orig_len
      @content = EthernetPacket.new(src.content.to_s)
    end
  end

  attr_reader :time_offset, :orig_len, :content
  attr_writer :time_offset, :orig_len, :content

  # A little awkward - if this is the first packet of the cpature, it has
  # a huge time_offset (the full timestamp).  So as a hack, reset the ts_sec
  # portion of its offset, and return that as the timestamp in seconds.
  def get_init_time
    seconds = @time_offset.to_i
    @time_offset -= seconds
    return seconds
  end

  # This puts the length of the packet and the length captured onto the
  # frame data that gets returned, but NOT the timestamp.  Keep that in mind.
  def to_s
    data = @content.to_s
    @orig_len = data.length   # Should this really be here?
    rltoh(@orig_len) + rltoh(data.length) + data
  end

  # Frame header, before any packet content, is 16 bytes
  def length
    16 + @content.length
  end

  # Special case here because we don't maintain this level's state inside of
  # a @hdr String.  Give each fragment the appropriate fraction of the
  # parent's time_offset.
  def fragment!(frag_options)
    return nil if @error or @content.class <= String
    frags = @content.fragment!(frag_options)
    if frags
      frags.collect! do |x|
        frag = self.dup
        frag.content = x
        frag.time_offset = @time_offset / frags.length
        frag
      end
    end
    return frags
  end

  # Create a hard copy of ourselves (a new Packet instance) from the string
  # representation of ourselves.
  def duplicate
    Packet.new(self, nil)
  end

end  # of class Packet


######  Graphical User Interface  ######

# Generic text input dialog.  Pass in the title of the window in a string
# variable, which will then get set to the text typed by the user when the
# dialog returns.
class InputDialog < FXDialogBox

  def initialize(owner, title, text)
    super(owner, title, DECOR_TITLE | DECOR_CLOSE)
    @ret = text
    @input = FXTextField.new(self, 24, :opts => FRAME_SUNKEN)
    @input.text = text

    # The ENTER key returns the current textfield string
    @input.connect(SEL_COMMAND) do
      @ret.replace(@input.text)
      self.handle(self, MKUINT(FXDialogBox::ID_ACCEPT, SEL_COMMAND), nil)
    end
  end

end  # of InputDialog class


# Packet fragmentation dialog
class FragmentDialog < FXDialogBox
  WINDOW_HEIGHT = 120
  WINDOW_WIDTH = 287
  COLUMN1 = 20
  COLUMN2 = 118
  COLUMN3 = 200
  ITEM_Y = 28
  BUTTON_Y = 84
  BUTTON_HEIGHT = 24
  BUTTON_WIDTH = 60

  def initialize(owner)
    super(owner, "Fragmentation", LAYOUT_EXPLICIT | DECOR_TITLE | DECOR_CLOSE |
          DECOR_RESIZE | LAYOUT_MIN_WIDTH | LAYOUT_MIN_HEIGHT,
          :height => WINDOW_HEIGHT, :width => WINDOW_WIDTH)
    radio_target = FXDataTarget.new(0)
    
    # Set our default values
    owner.frag_options.type      ||= :random
    owner.frag_options.bytes     ||= 1520
    owner.frag_options.fragments ||= 2
    
    # Radio buttons go on the left
    random = FXRadioButton.new(self, "Random", radio_target,
      FXDataTarget::ID_OPTION + 0, ICON_BEFORE_TEXT | LAYOUT_EXPLICIT |
      JUSTIFY_LEFT, :x => COLUMN1, :y => 16, :width => 80, :height => 20)
    mtu = FXRadioButton.new(self, "MTU", radio_target,
      FXDataTarget::ID_OPTION + 1, ICON_BEFORE_TEXT | LAYOUT_EXPLICIT |
      JUSTIFY_LEFT, :x => COLUMN1, :y => 16 + ITEM_Y, :width => 80,
      :height => 20)

    # Text box descriptions go in the middle
    FXLabel.new(self, "Max Count:", nil, LAYOUT_EXPLICIT | JUSTIFY_RIGHT,
                :x => COLUMN2, :y => 16, :width => 78, :height => 20);
    FXLabel.new(self, "Bytes:", nil, LAYOUT_EXPLICIT | JUSTIFY_RIGHT,
                :x => COLUMN2, :y => 16 + ITEM_Y, :width => 78, :height => 20);

    # Text fields go on the right
    fragments = FXTextField.new(self, 7, :opts => TEXTFIELD_INTEGER |
      FRAME_SUNKEN | LAYOUT_EXPLICIT, :x => COLUMN3, :y => 16,
      :width => 60, :height => 20)
    fragments.text = owner.frag_options.fragments.to_s
    bytes = FXTextField.new(self, 7, :opts => TEXTFIELD_INTEGER |
      FRAME_SUNKEN | LAYOUT_EXPLICIT, :x => COLUMN3, :y => 16 + ITEM_Y,
      :width => 60, :height => 20)
    bytes.text = owner.frag_options.bytes.to_s

    # OK and Cancel buttons go on the bottom
    button_ok = FXButton.new(self, "OK", :opts => LAYOUT_EXPLICIT |
      FRAME_NORMAL, :x => WINDOW_WIDTH - BUTTON_WIDTH - 16, :y => BUTTON_Y,
      :height => BUTTON_HEIGHT, :width => BUTTON_WIDTH,
      :target => self, :selector => ID_ACCEPT)
    button_cancel = FXButton.new(self, "Cancel", :opts => LAYOUT_EXPLICIT |
      FRAME_NORMAL, :x => WINDOW_WIDTH - BUTTON_WIDTH * 2 - 24, :y => BUTTON_Y,
      :height => BUTTON_HEIGHT, :width => BUTTON_WIDTH,
      :target => self, :selector => ID_CANCEL)

    # Set the radio button appropriately with memory
    if owner.frag_options.type == :random
      random.checkState = TRUE
    else
      mtu.checkState = TRUE
    end

    # Sync view -> model
    fragments.connect(SEL_CHANGED) do
      owner.frag_options.fragments = fragments.text.to_i
    end
    bytes.connect(SEL_CHANGED) do
      owner.frag_options.bytes = bytes.text.to_i
    end
    random.connect(SEL_COMMAND) do
      owner.frag_options.type = :random
      mtu.checkState = FALSE
    end
    mtu.connect(SEL_COMMAND) do
      owner.frag_options.type = :mtu
      random.checkState = FALSE
    end
  end

end  # of FragmentDialog


# Main GUI window
class MangleWindow < FXMainWindow
  WINDOW_HEIGHT = 400
  WINDOW_WIDTH  = 660
  WINDOW_TITLE  = "Pcap Mangle"
  BUTTON_WIDTH  = 100

  include EndianMess

  def create
    super
    show(PLACEMENT_SCREEN)
  end

  def initialize(app)
    super(app, WINDOW_TITLE, :width => WINDOW_WIDTH, :height => WINDOW_HEIGHT)
    packer = FXPacker.new(self, :opts => LAYOUT_FILL)

    # Add all the useful mangle buttons - right column
    button_list = FXPacker.new(packer, :opts => LAYOUT_FILL_Y |
      LAYOUT_SIDE_RIGHT | LAYOUT_FIX_WIDTH, :width => BUTTON_WIDTH)
    button_open = FXButton.new(button_list, "&Open", :opts => LAYOUT_SIDE_TOP |
      FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    button_open.connect(SEL_COMMAND) { load_pcap() }
    button_save = FXButton.new(button_list, "&Save", :opts => LAYOUT_SIDE_TOP |
      FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    button_save.connect(SEL_COMMAND) { save_pcap() }
    button_commit = FXButton.new(button_list, "&Commit",
      :opts => LAYOUT_SIDE_TOP | FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    button_commit.connect(SEL_COMMAND) { commit_order! }
    button_revert = FXButton.new(button_list, "&Revert",
      :opts => LAYOUT_SIDE_TOP | FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    button_revert.connect(SEL_COMMAND) { redraw_packets }
    button_follow = FXButton.new(button_list, "Follow",
      :opts => LAYOUT_SIDE_TOP | FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    button_follow.connect(SEL_COMMAND) { follow_flows }
    button_inv = FXButton.new(button_list, "Invert Sel",
      :opts => LAYOUT_SIDE_TOP | FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    button_inv.connect(SEL_COMMAND) { invert_selection }
    button_search = FXButton.new(button_list, "Text Search",
      :opts => LAYOUT_SIDE_TOP | FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    button_search.connect(SEL_COMMAND) { text_search }
    button_template = FXButton.new(button_list, "Templatize",
      :opts => LAYOUT_SIDE_TOP | FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    button_template.connect(SEL_COMMAND) { templatize }
    button_terminate = FXButton.new(button_list, "Terminate",
      :opts => LAYOUT_SIDE_TOP | FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    button_terminate.connect(SEL_COMMAND) { terminate }

    # Left column
    button_list = FXPacker.new(packer, :opts => LAYOUT_FILL_Y |
      LAYOUT_SIDE_RIGHT | LAYOUT_FIX_WIDTH, :width => BUTTON_WIDTH)
    button_time = FXButton.new(button_list, "Timestamp",
      :opts => LAYOUT_SIDE_TOP | FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    button_time.connect(SEL_COMMAND) { adjust_time_delta }
    button_fragment = FXButton.new(button_list, "&Fragment",
      :opts => LAYOUT_SIDE_TOP | FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    button_fragment.connect(SEL_COMMAND) { fragment_packets }
    button_segment = FXButton.new(button_list, "Segment",
      :opts => LAYOUT_SIDE_TOP | FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    button_segment.connect(SEL_COMMAND) { segment_packets }
    button_rand_ip = FXButton.new(button_list, "Mangle IPs",
      :opts => LAYOUT_SIDE_TOP | FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    button_rand_ip.connect(SEL_COMMAND) { mangle_ip }
    button_rand_port = FXButton.new(button_list, "Mangle Ports",
      :opts => LAYOUT_SIDE_TOP | FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    button_rand_port.connect(SEL_COMMAND) { mangle_port }
    button_426 = FXButton.new(button_list, "IPv4 > IPv6",
      :opts => LAYOUT_SIDE_TOP | FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    button_426.connect(SEL_COMMAND) { ip_426 }
    button_vlan = FXButton.new(button_list, "VLAN Tag",
      :opts => LAYOUT_SIDE_TOP | FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    button_vlan.connect(SEL_COMMAND) { vlan_tag }
    button_gre = FXButton.new(button_list, "GRE Tunnel",
      :opts => LAYOUT_SIDE_TOP | FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    button_gre.connect(SEL_COMMAND) { gre_tunnel }
    button_opts = FXButton.new(button_list, "Add Options",
      :opts => LAYOUT_SIDE_TOP | FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    button_opts.connect(SEL_COMMAND) { add_options }
    button_shuff4 = FXButton.new(button_list, "Shuffle 4",
      :opts => LAYOUT_SIDE_TOP | FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    button_shuff4.connect(SEL_COMMAND) { shuffle_four }
    button_weave = FXButton.new(button_list, "Weave Copy",
      :opts => LAYOUT_SIDE_TOP | FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    button_weave.connect(SEL_COMMAND) { interleave }

    # Table which contains our packet view
    @table = FXHorizontalFrame.new(packer, :opts => LAYOUT_FILL | FRAME_SUNKEN |
      FRAME_THICK | LAYOUT_SIDE_LEFT, :padLeft => 0, :padRight => 0,
      :padTop => 0, :padBottom => 0, :hSpacing => 0, :vSpacing => 0)
    @column =  FXList.new(@table, :opts => LAYOUT_FILL_Y | LAYOUT_FILL_X |
      LIST_EXTENDEDSELECT)
    @column.backColor = FXRGB(240, 240, 255)
    @column.font = FXFont.new(app, 'system', 8)
    @column.connect(SEL_KEYPRESS, method(:on_keypress))

    # Our actual packet content list
    @packets = []
    @clipboard = []
    @start_time = 0.0
    @frag_options = Struct.new(:type, :bytes, :fragments).new
  end  # of initialize

  attr_reader :frag_options

  # Return a list of selected list indices
  def get_selected
    sel = []
    @column.numItems.times do |i|
      sel << i if @column.itemSelected?(i)
    end
    return sel
  end

  # Set the list of selected indicies
  def set_selected(sel)
    @column.numItems.times do |i|
      if sel.include?(i)
        @column.selectItem(i)
      else
        @column.deselectItem(i)
      end
    end
  end

  # Iterator that yields row number (starts at 0) and its packet number
  # (starts at 1) for ever selected row in the GUI.
  def selected_rows
    @column.numItems.times do |i|
      if @column.itemSelected?(i)
        num = @column.getItemText(i).to_i - 1
        yield i, num
      end
    end
  end

  # Choose a file into which we save our packet capture
  def save_pcap
    return nil if @packets.empty?
    dialog = FXFileDialog.new(self, "Save Pcap File")
    dialog.patternList = [ "Packet Capture (*.pcap)" ]
    file = nil
    file = dialog.filename.first if dialog.execute == 1
    return nil unless file
    commit_order!

    # Save our packet list to a file, one packet at a time.
    File.open(file, 'w') do |pcap|
      pcap.print(@pcap_header)
      timestamp = @start_time
      @packets.each do |pkt|
        #pkt.checksum!    # Uncomment to test checksumming
        timestamp += pkt.time_offset
        pkt = pkt.to_s
        seconds = rltoh(timestamp.to_i)
        microseconds = rltoh(((timestamp - timestamp.floor) * 1000000).to_i)
        pcap.print("#{seconds}#{microseconds}")
        pcap.print(pkt)
      end
    end
  end

  # Load the given file or, absent that, launch a modal file dialog
  # Optionally the last argument can be an integer [or something supporting
  # the .to_i() method] specifying the maximum number of packets to read
  # from the given capture(s).
  def load_pcap(*files)
    max_packets = 0xFFFFFFFF

    # Did the user instruct us to limit our packet reading?
    if files.length > 1 and files.last.to_i.to_s == files.last.to_s
      max_packets = files.pop.to_i
    end

    if files.empty?
      dialog = FXFileDialog.new(self, "Open Pcap Files")
      dialog.selectMode = SELECTFILE_MULTIPLE;
      dialog.patternList = [ "Packet Captures (*.pcap)" ]
      files = dialog.filenames.dup if dialog.execute !=0
    end
    return nil if files.empty?
    
    # We have our file list, let's open it.  Destroy whatever we have now.
    @packets = []
    @pcap_header = nil
    files.each do |fname|
      pkt_list = []
      timestamp = 0.0
      File.open(fname) do |pcap|
        hdr = pcap.read(24)
        @pcap_header = hdr if @packets.empty?
        file_len = pcap.lstat.size - 15
        while pcap.pos < file_len do
          pkt_list << Packet.new(pcap, timestamp)
          break if pkt_list.length + @packets.length == max_packets
          timestamp += pkt_list.last.time_offset
        end
      end
      st_time = pkt_list.first.get_init_time()
      @start_time = st_time if @packets.empty?
      @packets += pkt_list
      break if @packets.length == max_packets
    end  # of files.eaach
    
    # Complete update of our display
    redraw_packets()
  end  # of load_pcap()

  # Redraw the list of packets in our buffer completely
  def redraw_packets()
    @column.clearItems()
    num = 1
    (@packets || []).each do |packet|
      @column.appendItem("#{num}: #{packet.inspect}")
      num += 1
    end
  end

  # The user struck a key within the packet list
  def on_keypress(sender, selector, e)
    if e.code == KEY_KP_Add or e.code == KEY_plus
      slide_selection_down()
    elsif e.code == KEY_KP_Subtract or e.code == KEY_minus
      slide_selection_up()
    elsif e.code == KEY_x
      cut_selection(true, true)
    elsif e.code == KEY_c
      cut_selection(true, false)
    elsif e.code == KEY_KP_Delete or e.code == KEY_Delete
      cut_selection(false, true)
    elsif e.code == KEY_Insert or e.code == KEY_KP_Insert or e.code == KEY_v
      paste_clipboard
    elsif e.code == KEY_Escape
      unselect_all
    end
    return false   # so it gets passed on to other handlers
  end

  # Move all the selected packets up one space, unless there's no room
  def slide_selection_up
    return nil if @column.currentItem < 0
    selected_rows do |i,_|
      return nil if i == 0
      @column.moveItem(i - 1, i)
    end
  end

  # Move all the slected packets down one space, unless there's no room
  def slide_selection_down
    return nil if @column.currentItem < 0
    (@column.numItems - 1).downto(0) do |i|
      if @column.itemSelected?(i)
        return nil if i >= @column.numItems - 1
        @column.moveItem(i + 1, i)
      end
    end
  end

  # Copy the selected packets into our buffer, cutting them if so requested
  def cut_selection(do_copy = true, do_cut = false)
    @clipboard = [] if do_copy
    i = 0
    while i < @column.numItems do
      if @column.itemSelected?(i)
        @clipboard << @column.getItemText(i) if do_copy
        if do_cut
          @column.removeItem(i)
          i -= 1
        end
      end
      i += 1
    end
  end

  # Put the clipboard packets at the current position, displacing the currently
  # selected item.  If there is no currently selected item, append clipboard.
  def paste_clipboard
    return nil if @clipboard.empty?
    select_list = []
    pos = @column.currentItem
    pos = @column.numItems if pos < 0
    @clipboard.each do |pkt_text|
      if pos == @column.numItems
        @column.appendItem(pkt_text)
      else
        @column.insertItem(pos, FXListItem.new(pkt_text))
      end
      select_list << pos
      pos += 1
    end

    # Now go back and highlight all the new items
    set_selected(select_list)
  end

  # Just don't select anything
  def unselect_all
    @column.numItems.times { |i| @column.deselectItem(i) }
  end

  # Modify our actual packet list so it matches the display
  def commit_order!
    new_packets = []
    read_packets = Set.new
    @column.numItems.times do |i|
      pkt_index = @column.getItemText(i).to_i - 1

      # Make hard copies on duplicate source indicies to prevent sharing members
      if read_packets.include?(pkt_index)
        new_packets << @packets[pkt_index].duplicate
      else
        new_packets << @packets[pkt_index]
        read_packets.add pkt_index
      end
    end
    @packets = new_packets
    redraw_packets
  end

  # Bring up a small dialog for fragmentation options, then fragment,
  # commit order, and redraw.
  def fragment_packets
    if FragmentDialog.new(self).execute == 1
      new_packets = []
      @column.numItems.times do |i|
        pkt = @packets[@column.getItemText(i).to_i - 1]
        if @column.itemSelected?(i)
          frags = pkt.fragment!(@frag_options)
          if frags
            new_packets += frags
          else
            new_packets << pkt
          end
        else
          new_packets << pkt
        end
      end
      @packets = new_packets
      redraw_packets
    end
  end

  # Select all the packets that belong to any of the flows of any of the
  # currently selected packets
  def follow_flows
    flows = {}

    # First build our follow hash
    selected_rows do |i,num|
      flow = @packets[num].flow_id
      flows[flow] = true
    end
    return nil if flows.empty?

    # Now select every packet that has a flow_id in our hash
    @column.numItems.times do |i|
      unless @column.itemSelected?(i)
        flow = @packets[@column.getItemText(i).to_i - 1].flow_id
        @column.selectItem(i) if flows[flow]
      end
    end
  end

  # Deterministically mangle all selected IP packets
  def mangle_ip
    salt = (0..16).to_a.collect { rand(256).chr }.join
    selected_rows do |i, num|
      @packets[num].mangle_ip!(salt)
      @column.setItemText(i, "#{num + 1}: #{@packets[num].inspect}")
    end
  end

  # Deterministically mangle all selected TCP or UDP packets
  def mangle_port
    salt = (0..16).to_a.collect { rand(256).chr }.join
    selected_rows do |i, num|
      @packets[num].mangle_port!(salt)
      @column.setItemText(i, "#{num + 1}: #{@packets[num].inspect}")
    end
  end

  # Convert selected IPv4 packets to IPv6 packets.  Doesn't work on fragments.
  def ip_426
    selected_rows do |i, num|
      @packets[num].ip_426!
      @column.setItemText(i, "#{num + 1}: #{@packets[num].inspect}")
    end
  end

  # VLAN tag the selected packets
  def vlan_tag
    vlan_id = rand(16).chr + rand(256).chr
    selected_rows do |i, num|
      @packets[num].vlan_tag!(vlan_id)
      @column.setItemText(i, "#{num + 1}: #{@packets[num].inspect}")
    end
  end

  # Put the selected packets into an IPv4 GRE tunnel
  def gre_tunnel
    src = "\x0a\x01" + rand(256).chr + rand(256).chr
    dst = "\x0a\x02" + rand(256).chr + rand(256).chr
    ip_hdr =  "\x45\x00\xAA\xAA\xBB\xBB"  # version, lengths, ToS, ID
    ip_hdr << "\x00\x00\x40\x2f\xCC\xCC"  # flags, ttl, proto, checksum
    ip_hdr << src + dst
    selected_rows do |i, num|
      @packets[num].gre_tunnel!(ip_hdr)
      @column.setItemText(i, "#{num + 1}: #{@packets[num].inspect}")
    end
  end

  # Add options to every header type that supports it.  Those that support
  # it will define an add_options!() method.  All others will merely pass
  # the request along.  After calling this, call checksum!
  def add_options
    selected_rows do |i, num|
      @packets[num].add_options!
      @packets[num].checksum!
      @column.setItemText(i, "#{num + 1}: #{@packets[num].inspect}")
    end
  end

  # Select the unselected items and vice-versa
  def invert_selection
    @column.numItems.times do |i|
      if @column.itemSelected?(i)
        @column.deselectItem(i)
      else
        @column.selectItem(i)
      end
    end
  end

  # Break each selected data-bearing packet into segments (OSI layer 4
  # segmentation) containing one payload byte per packet.  TCP Only!
  def segment_packets
    new_packets = []
    @column.numItems.times do |i|
      pkt = @packets[@column.getItemText(i).to_i - 1]
      if @column.itemSelected?(i)
        frags = pkt.segment!
        if frags
          new_packets += frags
        else
          new_packets << pkt
        end
      else
        new_packets << pkt
      end
    end
    @packets = new_packets
    redraw_packets
  end

  # Shuffle the selected packets in groups of four.  This preserves general
  # order while still ensuring small-scale reordering.
  def shuffle_four
    shuff = []
    sel = get_selected
    sel.each do |i|
      shuff << i
      if shuff.length == 4 || i == sel.last
        res = shuff.dup
        res.length.times do |x|
          y = rand(res.length)
          res[x], res[y] = res[y], res[x] unless x == y
        end
        res = res.collect { |x| @column.getItemText(x) }
        res.length.times do |x|
          @column.setItemText(shuff[x], res[x])
        end
        shuff = []
      end
    end
    set_selected(sel)
  end

  # Select all packets which contain the given text.  Text can include hex chars
  def text_search
    text = ''
    InputDialog.new(self, "Search for:", text).execute
    return nil if text.empty?

    # Convert "\xHH" to a raw byte denoted by the two hex digits HH
    res = ''
    state = :normal
    hex = ''
    text.each_byte do |c|
      if state == :normal
        if c.chr == '\\'
          state = :slash
        else
          res << c.chr
        end
      elsif state == :slash
        if c.chr == 'x'
          state = :hex
          hex = ''
        else
          state = :normal
          if c.chr == 'n'
            res << "\n"
          elsif c.chr == 'r'
            res << "\r"
          elsif c.chr == 't'
            res << "\t"
          elsif c.chr == '0'
            res << "\0"
          else
            res << c.chr
          end
        end
      elsif state == :hex
        hex << c.chr
        if hex.length == 2
          state = :normal
          res << hex.to_i(16).chr
        end
      end
    end

    # Perform the actual search, highlighting (and un-highlighting) as we go.
    @column.numItems.times do |i|
      pkt = @packets[@column.getItemText(i).to_i - 1].to_s
      if pkt.include? res
        @column.selectItem(i)
      else
        @column.deselectItem(i)
      end        
    end
  end

  # Adjust the timestamp (seconds)
  def adjust_time_delta
    pkt = nil
    selected_rows do |i, num|
      pkt = @packets[num]
      break
    end

    # Did we find a selected packet?  If so, adjust its timestamp
    if pkt
      text = (1000 * pkt.time_offset).to_s
      InputDialog.new(self, "Delta (ms):", text).execute
      return nil if text.empty?
      pkt.time_offset = text.to_f / 1000

    # We didn't find a timestamp?  Adjust the file's overall start time
    else
      text = @start_time.to_s
      InputDialog.new(self, "Timestamp:", text).execute
      return nil if text.empty?
      @start_time = text.to_i
    end
  end

  # Create a mangled copy of each selected packet
  def interleave
    select_list = []
    copy_list = get_selected()
    coff = 0

    copy_list.each do |i|
      pkt_index = @column.getItemText(i + coff).to_i - 1
      @packets << @packets[pkt_index].duplicate
      pkt_text = "#{@packets.length}: #{@packets.last.inspect}"
      coff += 1
      if i + coff == @column.numItems
        @column.appendItem(pkt_text)
      else
        @column.insertItem(i + coff, FXListItem.new(pkt_text))
      end
      select_list << i + coff
    end

    # Now go back and highlight all the new items, then mangle those packets
    set_selected(select_list)
    mangle_ip
  end

  # Templatize the sent packets (convert to 10.0.0.1 and 10.0.0.2 for IPv4,
  # abcd::1 and abcd::2 for IPv6)
  def templatize
    selected_rows do |i, num|
      @packets[num].mangle_ip!(:template)
      @column.setItemText(i, "#{num + 1}: #{@packets[num].inspect}")
    end
  end

  # Terminate (with an RST) all of the flows of any of the currently
  # selected packets.
  def terminate
    flows = {}

    # First build our follow hash, keeping track of src, dst, ports, seq
    # and ack of the last seen packet within each flow.
    selected_rows do |i,num|
      flow = @packets[num].flow_id
      rst = @packets[num].tcp_rst
      if rst
        rst << i
        flows[flow] = rst
      end
    end
    return nil if flows.empty?

    # Next, order the trailing packets for each flow
    states = []
    flows.each do |_,rst|
      indx = rst.pop
      states << [ indx, rst ]
    end
    states = states.sort.reverse

    # Now create the reset packets at the end of our packet list
    # State objects are in the form:  [ src, dst, sport, dport, seq, ack ]
    states.each do |i, rst|
      i += 1
      @packets << Packet.new(rst.reverse.join, nil)
      @packets.last.checksum!
      pkt_text = "#{@packets.length}: #{@packets.last.inspect}"
      if i == @column.numItems
        @column.appendItem(pkt_text)
      else
        @column.insertItem(i, FXListItem.new(pkt_text))
      end
    end
  end

end  # of class MangleWindow


# Start the application
if __FILE__ == $0
  FXApp.new do |app|
    window = MangleWindow.new(app)
    app.create
    window.load_pcap(*ARGV) unless ARGV.empty?
    app.run
  end
end
