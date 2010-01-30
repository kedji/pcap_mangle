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

end  # of module PacketNest

# Module for endian/integer conversions
module EndianMess

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

  # Ruby Long to Host - Convert a Fixnum to a 4-byte host-byte-order string
  def rltoh(num)
    str = ''
    4.times do
      str << (num & 0xFF).chr
      num >>= 8
    end
    str
  end

end  # of module EndianMess


######  Packet Headers in Descending Order  ######

# Class that holds TCP packets
class TCPPacket

  include PacketNest
  include EndianMess

  def initialize(data)
    @error = nil
    @hdr = ''
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
    "#{src} > #{dst}"
  end

  # Recalculate the checksum field for this TCP packet.  Thanks to the
  # TCP psuedo-header, the 8 bytes of the IP header containing source and
  # destination address need to be provided.  *sigh*  Layering violations.
  def checksum!(ip_bytes)
    return nil if @error

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

end  # of class TCPPacket


# Class that holds UDP packets
class UDPPacket

  include PacketNest
  include EndianMess

  def initialize(data)
    @error = nil
    @hdr = ''
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
    @hdr[6,2] = "\x00\x00"
  end

end  # of class UDPPacket


# Class that holds IP packets
class IPPacket

  include PacketNest
  include EndianMess

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

    # Examine the protocol field for types we recognize
    if next_layer == 6
      @content = TCPPacket.new(data)
    elsif next_layer == 17
      @content = UDPPacket.new(data)
    else
      @content = data
    end
  end

  def details()
    return @error if @error
    src = IPAddr.new(ntorl(@hdr[12,4]), Socket::AF_INET)
    dst = IPAddr.new(ntorl(@hdr[16,4]), Socket::AF_INET)
    "#{src}:#{dst}"
  end

  def checksum!
    return nil if @error
    @hdr[10,2] = "\x00\x00"  # zero the checksum initially

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

    # If this packet contains TCP or UDP, tell it to checksum as well!
    # And because we're nice, give it information it needs for psuedo-header.
    if @content.class <= TCPPacket or @content.class <= UDPPacket
      @content.checksum!(@hdr[12,8])
    end
  end    

end  # of class IPPacket


# Class that holds Ethernet packets.  Pretty simple, really.
class EthernetPacket

  include PacketNest
  include EndianMess

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
  include EndianMess

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

  # This puts the length of the packet and the length captured onto the
  # frame data that gets returned, but NOT the timestamp.  Keep that in mind.
  def to_s
    data = @content.to_s
    @orig_len = data.length   # Should this really be here?
    rltoh(@orig_len) + rltoh(data.length) + data
  end

end  # of class Packet


######  Graphical User Interface  ######

# Main GUI window
class MangleWindow < FXMainWindow
  WINDOW_HEIGHT = 320
  WINDOW_WIDTH  = 480
  WINDOW_TITLE  = "Pcap Mangle"
  BUTTON_WIDTH  = 90

  include EndianMess

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
    button_save.connect(SEL_COMMAND) { save_pcap() }

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
  end  # of initialize

  # Choose a file into which we save our packet capture
  def save_pcap
    return nil if @packets.empty?
    dialog = FXFileDialog.new(self, "Save Pcap File")
    dialog.patternList = [ "Packet Capture (*.pcap)" ]
    file = nil
    file = dialog.filename.first if dialog.execute == 1
    return nil unless file

    # Save our packet list to a file, one packet at a time.
    File.open(file, 'w') do |pcap|
      pcap.print(@pcap_header)
      timestamp = @start_time
      @packets.each do |pkt|
        pkt.checksum!   # This doesn't need to happen every time
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
    @column.clearItems()
    num = 1
    @packets.each do |packet|
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
    @column.numItems.times do |i|
      if @column.itemSelected?(i)
        return nil if i == 0
        @column.moveItem(i - 1, i)
      end
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
      @column.insertItem(pos, FXListItem.new(pkt_text))
      select_list << pos
      pos += 1
    end

    # Now go back and highlight all the new items
    @column.numItems.times do |i|
      if select_list.include?(i)
        @column.selectItem(i)
      else
        @column.deselectItem(i)
      end
      @column.currentItem = select_list.first
    end
  end

  # Just don't select anything
  def unselect_all
    @column.numItems.times { |i| @column.deselectItem(i) }
  end

end  # of class MangleWindow



# Start the application
if __FILE__ == $0
  FXApp.new do |app|
    MangleWindow.new(app)
    app.create
    app.run
  end
end
