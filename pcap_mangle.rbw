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

include Fox


# Module for mixing in that assists with recursively examining packets and
# their contained headers
module PacketNest

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
      next_inspect = "[Data #{@content.length}]"
    else
      next_inspect = @content.inspect()
    end
    "#{proto}#{next_inspect}"
  end

  # Net to Ruby Long - Convert a host-byte-order string into a Fixnum
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

end  # of module PacketNest


######  Packet Headers in Descending Order  ######

# Class that holds IP packets
class IPPacket

  include PacketNest

  def initialize(data)
    @error = nil
    hdr_len = (data[0].to_i - 0x40) * 4
    if data.length < hdr_len or hdr_len < 20
      @error = "Truncated"
      @content = data
      return nil
    end

    # Grab our header
    @hdr = data[0,hdr_len]
    data[0,hdr_len] = ''
    next_layer = @hdr[9]

    # Examine the protocol field for types we recognize
    @content = data
  end

  def details()
    src = IPAddr.new(ntorl(@hdr[12,4]), Socket::AF_INET)
    dst = IPAddr.new(ntorl(@hdr[16,4]), Socket::AF_INET)
    "#{src} > #{dst}"
  end

end  # of class IPPacket


# Class that holds Ethernet packets.  Pretty simple, really.
class EthernetPacket

  include PacketNest

  # Pull off our own data, then construct interior headers we recognize
  def initialize(data)
    @error = nil
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

end  # of class EthernetPacket


# Class that defines an individual packet (frame would be a more precise
# term).  Translations on this packet are performed as methods within this
# class.
class Packet

  include PacketNest

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
      abs_time = htorl(frame_hdr[0,4]) + htorl(frame_hdr[4,4]).to_f / 1000000
      @time_offset = abs_time - last_time
      @orig_len = htorl(frame_hdr[12,4])
      cap_len = htorl(frame_hdr[8,4])

      # Now get the payload of this frame
      payload = src.read(cap_len)
      @content = EthernetPacket.new(payload)
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


######  Graphical User Interface  ######

# Main GUI window
class MangleWindow < FXMainWindow
  WINDOW_HEIGHT = 320
  WINDOW_WIDTH  = 480
  WINDOW_TITLE  = "Pcap Mangle"
  BUTTON_WIDTH  = 90

  def create
    super
    show(PLACEMENT_SCREEN)
  end

  def initialize(app)
    super(app, WINDOW_TITLE, :width => WINDOW_WIDTH, :height => WINDOW_HEIGHT)
    packer = FXPacker.new(self, :opts => LAYOUT_FILL)

    # Add all the useful mangle buttons
    button_list = FXPacker.new(packer, :opts => LAYOUT_FILL_Y |
      LAYOUT_SIDE_RIGHT | LAYOUT_FIX_WIDTH, :width => BUTTON_WIDTH)
    button_open = FXButton.new(button_list, "&Open", :opts => LAYOUT_SIDE_TOP |
      FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    button_open.connect(SEL_COMMAND) { load_pcap() }
    button_save = FXButton.new(button_list, "&Save", :opts => LAYOUT_SIDE_TOP |
      FRAME_RAISED | FRAME_THICK | LAYOUT_FILL_X)
    #button_save.connect(SEL_COMMAND) { save_pcap() }

    # Table which contains our packet view
    @table = FXHorizontalFrame.new(packer, :opts => LAYOUT_FILL | FRAME_SUNKEN |
      FRAME_THICK | LAYOUT_SIDE_LEFT, :padLeft => 0, :padRight => 0,
      :padTop => 0, :padBottom => 0, :hSpacing => 0, :vSpacing => 0)
    @cols = []
    #@cols << FXList.new(@table, :opts => LAYOUT_FILL_Y | LAYOUT_FIX_WIDTH |
    #  LIST_MULTIPLESELECT, :width => 80)
    @cols << FXList.new(@table, :opts => LAYOUT_FILL_Y | LAYOUT_FILL_X |
      LIST_EXTENDEDSELECT)
    @cols[0].backColor = FXRGB(240, 240, 255)
    @cols[0].font = FXFont.new(app, 'system', 8)

    # Our actual packet content list
    @packets = []
    @start_time = 0.0
  end  # of initialize

  # Load the given file or, absent that, launch a modal file dialog
  def load_pcap(*files)
    if files.empty?
      dialog = FXFileDialog.new(self, "Open Pcap Files")
      dialog.selectMode = SELECTFILE_MULTIPLE;
      dialog.patternList = [ "Packet Captures (*.pcap)" ]
      files = dialog.filenames.dup if dialog.execute !=0
    end
    return nil if files.empty?
    
    # We have our file list, let's open it.  Destroy whatever we have now.
    @packets = []
    files.each do |fname|
      pkt_list = []
      timestamp = 0.0
      File.open(fname) do |pcap|
        hdr = pcap.read(24)
        file_len = pcap.lstat.size - 15
        while pcap.pos < file_len do
          pkt_list << Packet.new(pcap, timestamp)
          timestamp += pkt_list.last.time_offset
        end
      end
      st_time = pkt_list.first.get_init_time()
      @start_time = st_time if @packets.empty?
      @packets += pkt_list
    end  # of files.eaach
    
    # Complete update of our display
    redraw_packets()
  end  # of load_pcap()

  # Redraw the list of packets in our buffer completely
  def redraw_packets()
    @cols[0].clearItems()
    num = 0
    @packets.each do |packet|
      @cols[0].appendItem("#{num}: #{packet.inspect}")
      num += 1
    end
  end

end  # of class MangleWindow




#pcap = File.open ARGV[0]
#hdr = pcap.read(24)
#packets = []
#timestamp = 0.0
#while pcap.pos < pcap.lstat.size - 15 do
#  packets << Packet.new(pcap, timestamp)
#  timestamp += packets.last.time_offset
#end


# Start the application
if __FILE__ == $0
  FXApp.new do |app|
    MangleWindow.new(app)
    app.create
    app.run
  end
end
