#    code compressor: compacts 6510/6502 assembler code into runnable assembler 
#    Copyright (C) 2018 John Lutz
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
import hashlib
import sys
#JKLO from overlap import *

DEBUG_ONE_INSTRUCTION = 0
DEBUG_CREATE = 0
DEBUG_HASH_SEGMENT=0
DEBUG_REPORT=0
DEBUG_ALL_INSTRUCTIONS=0
DEBUG_READ_ALL_OF_SEGMENT=0
DEBUG_ONE_INSTRUCTION_PRINT_INSTRUCTION=0
 
all_found_segments={}
all_found_addresses={}
all_only_found_addresses={}

block_id = 0
largest_found_block={}
largest_found_block[block_id]={}
largest_found_block[block_id]['size'] = 0
largest_found_block[block_id]['addr'] = 0

class addr(object):

  begining_address=0  # first place of all searches
  starting_address = 0
  ending_address=0   # last entry in code

  ending_byte_address= 0

  current_address=0   # currently working on
  previous_address=0  # just before current
  next_address = 0

  next_all_address = 0 #searching all code

  starting_segment_address=0 # current segment starting address
 
class sizer(object):
  window_segment_size = 6
  current_segment_size = 0 
  minimum_segment_size = 6
  maximum_segment_size = 50

class Scan():
  def __init__(self):
    next_address = 0
  
    from assem import array_aid
    from assem import ending_address
    global array_aid
    global addr
    global ending_address 

  def one_instruction(self, address=addr.begining_address):
    global array_aid
    global addr


    segment = Segment(0,address,0)
    new_current_data = 0


 
    if (address==addr.begining_address):
        addr.current_address = address
        addr.previous_address = address
    else: 
 
               
        address = addr.current_address
        addr.previous_address = address
  
    segment.address = address
    #
 

    #6502

    if (segment.address < addr.ending_address):
      print("read @ array: " + str(array_aid[address]))
      got_mnemonic = array_aid[segment.address] #read_mnemonic
    else:
      print("fail end @ " + str(segment.address))
      return segment

    segment.size = got_mnemonic['byte_cnt']


    segment.next_address += segment.size #+address
 
    segment.label = got_mnemonic['operator']

    segment.data = got_mnemonic['operand']


    # in 6502, 2 bytes for instruction AND data
    #          3 bytes for 1 instr and 16bit data




    addr.current_address += segment.size
 

    if(DEBUG_ONE_INSTRUCTION_PRINT_INSTRUCTION):
      print("segment.label=" + segment.label)
      print("segment.data="  + segment.data)

    if(DEBUG_ONE_INSTRUCTION):
      print ("segment_address=" + str(array_aid[segment.address]))
 
      print("current_address = + " + str(addr.current_address) + ";")
      print("previous_address = + " + str(addr.previous_address) + ";")
      print("segment.next_address = + " + str(segment.next_address) + ";")

      print("\n")

    

    return segment


  def all_instructions(self, read_segment, new_index=addr.begining_address):
    global addr

    if(DEBUG_ALL_INSTRUCTIONS):
      print("\n all_instructions: segment=" + str(read_segment) ) # + " address=" +str(index)+"\n")
    # compare current newly read instruction against read_segment
    # read until read_segment code syncs with new instructions
    # don't need to save segment because we have it as IN parameter
    # Return the size of this new segment
    # segment size is data agnostic
    #i=0
    j=0
    #j=starting_segment_address
    j =list(read_segment.keys())
    j.sort()
    sorted_list = j
    max_list = len(j)
    print ("new_index = " + str(new_index))
    i=new_index
    z = 0
    start_all_address = i

    print("j=" + str(j))
    print("ending_address=" + str(addr.ending_address)+ "\n")
    
    while (z< max_list):
      if (i>= addr.ending_address):
        return addr.ending_address
      print("before one instruction")
      cur_inst = self.one_instruction(i)
      if (z==0):
         pretty_first_address_found = cur_inst.address
      
      if (cur_inst.address >= addr.ending_address):
        return addr.ending_address

      if(DEBUG_ALL_INSTRUCTIONS):
        print("Z after one_instruction=" + str(z) + " = max_list=" +str(max_list))
        print("cur_inst.label =" + cur_inst.label)
        print("cur_inst.data  =" + cur_inst.data)
        print("i1=" + str(i))
        print("cur_inst.next_address=" + str(cur_inst.next_address)+ "\n")
      # p == a
      # since we already have unbranched segments, don't worry about branches or RTS
      # pattern in text string?
      # p[i..M], a[1..N]
 
      if ((read_segment[j[z]]['segment'].label == cur_inst.label) and 
          (read_segment[j[z]]['segment'].data  == cur_inst.data)):

        ##j+=1
        ###j = read_segment.__next__()
        z += 1
        if(z>=max_list):
          # REFERENCE: (read_segment[j[0]]['segment'].address)
          original_address = read_segment[j[0]]['segment'].starting_segment_address
          print("FOUND new address at " +str(pretty_first_address_found)+ " from original address @ "+ str(original_address) + " !!!!!!!!!!!!!!!!!!!!")
          
          if (cur_inst.data):
            addr.next_all_address = start_all_address + len(cur_inst.data) + 1
          else:
            addr.next_all_address = start_all_address + 1   
          print("Found addr_next_address=" + str(addr.next_all_address))
          #return start_all_address
          return pretty_first_address_found
        if(DEBUG_ALL_INSTRUCTIONS):
          print("IF i=" + str(i))
          print("z="+ str(z) )
          print( " j[z]=" +str(j[z]))
          print("cur_inst.label=" + cur_inst.label)
          print("cur_inst.data=" + cur_inst.data)

          print("read_segment.address =" + str(read_segment[j[z]]['segment'].address))
          print("read_segment.label   =" + read_segment[j[z]]['segment'].label+"\n")
 
      else:
        #i = i-j+2
        z = 0
        j = sorted_list
        start_all_address = cur_inst.address 

         
      i+= cur_inst.size  #1

    #if (j > read_segment[j].size  or i > ending_address):
    #  return i - read_segment[j].size  # found one! i-M
    print("final : maxlist=" + str(max_list)+" i="+str(i))
    #
    # we've found more in the code than we want, otherwise exact        
    addr.next_all_address = i

    return i                      # didn't find any!




class Segment(Scan):
  def __init__(self, size, address, count):
    self.size = size
    self.address = address
    self.count = count
    self.next_address = address
    self.label = ''
    self.new_key='segment'
    self.count=0
    self.ending_segment_address =0 
    scan = Scan()
    global Address
    self.addr = addr
    self.starting_segment_address = 0
    #self.next_address = 0
    addresses = [0]
   
  def empty(segment):
    segment.address = 0
    segment.label = 'JMP'
    segment.size = 0
    segment.count = 0
    segment.next_address = 0
    segment.ending_segment_address = 0
    return segment
  def copy(segment):
    return_segment.hashid = ''
    
    return_segment.address = segment.address
    return_segment.label = segment.label
    return_segment.size = segment.size
    return_segment.count = segment.count
    return_segment.next_address = next_address
    

  def __getitem__(self,key):
    if (key=='segment'):
      self.new_key = 'segment'
      return self
    elif (key == 'count'):
      self.new_key = 'count'
      return self.count 
    elif (key == 'addresses'):
      self.new_key = 'addresses'
      return self.addresses 
    elif (key == 'hashid'):
      self.new_key = 'hashid'
      return self.hashid
    elif (key == 'ending_segment_address'):
      self.new_key = "ending_segment_address"
      return self.ending_segment_address
    elif (key == 'starting_segment_address'):
      self.new_key = 'starting_segment_address'

      return self.starting_segment_address


  def __add__(self,other):
    total_size = self.size + other.size
    total_address = self.address
    return Segment(total_size, total_address, count)

  def __setitem__(self,instance,value):

    #print("__setitem__=instance=" +str(instance) +" value="+ str(value))
    if self.new_key=='hashid':
      self['segment'].hashid = value

    elif self.new_key=='count':

      self['segment'].count = value
    elif self.new_key=='ending_segment_address':

      self['segment'].ending_segment_address = value

 
    elif self.new_key=='addresses':
      print("ADDRESSES")
      self['segment'].addresses.append(value)

    elif self.new_key=='starting_segment_address':
      self.starting_segment_address = value 
    return instance

  #def __repr__(self): 
  #  if (self.new_key == 'segment'):
  #    return format(self.address,'02x')

  def __str__(self):
    if (self.new_key=='hashid'):

      return self.hashid
    elif (self.new_key=='ending_segment_address'):

      return self.ending_segment_address
    elif (self.new_key=='addresses'):

      return self.addresses
    elif (self.new_key== 'segment'):
      return "self" # return format(self.address,'02x') #self
  
    elif (self.new_key == 'starting_segment_address'):
      return str(self.starting_segment_address)
    else:
      return format(self.starting_segment_address,'02x')

  def hash_it(self, hash_string):

    if(hash_string):
      hashed_object = hashlib.md5(str(hash_string).encode('utf-8'))
  
      self.hashid = hashed_object.hexdigest()
      return self.hashid
    else:
      print("error error")
      return ''


  def hash_segment(self, read_segment, seg_size):
    total_hash = ''
    for (key,val) in read_segment.items():

      if(DEBUG_HASH_SEGMENT):
        print("vallab:" + val['segment'].label + " DATA: " + val['segment'].data )
      total_hash += val['segment'].label + val['segment'].data  

    total_hash += str(seg_size)
    
    if (DEBUG_HASH_SEGMENT):
      print('end hash segment total_hash=' + total_hash)

    return self.hash_it(total_hash)




  scan = Scan()
  empty=False
  hashid = ''
  ending_segment_address = 0
  total_hashid = ''
  new_key='segment'
  data = ''
  size=0
  found_address={}
  found_address[0]=0
  count=0
  next_address=0

  def start_new_segment(self,address,segment):
    print("start_new") 
    read_instruction_data = self.scan.one_instruction(address)
    #address = read_instruction_data.next_address
    if (read_instruction_data.address >= addr.ending_address):
        address= addr.ending_address
    hash_address = read_instruction_data.hash_it(address)
    segment = { address: {'starting_segment_address': address, 'segment': read_instruction_data, 'hashid': hash_address, 'ending_segment_address': 0, 'size':0}}
    return segment                                          

  def create_segment(self, address):
    scan = Scan()
    global sizer 
    global addr
    #JOHNL TODO remove dupliate
    addr.starting_segment_address = address

    starting_segment_address = address
    #ending_segment_address= addr.ending_address

    #if (self.next_address>0):
    #  address = self.next_address

    #TODO new_segment resets, 1)pass in!
    new_segment={}
    final_new_segment={}
    
    new_segment = self.start_new_segment(address,new_segment)
    final_new_segment= self.start_new_segment(address,final_new_segment)
    
    if((final_new_segment[address]['starting_segment_address'] == addr.ending_address) or (new_segment[address]['starting_segment_address'] == addr.ending_address)): 
      return new_segment


    #build up that new segment
    #while( sizer.current_segment_size < sizer.window_segment_size): 
    while (address < addr.ending_address and sizer.current_segment_size<sizer.window_segment_size):


      # Warning: Modifies current_address (global implcit counter)
      #try:
      read_instruction_data = scan.one_instruction(address)

      address = read_instruction_data.address
      next_address = read_instruction_data.next_address
      print("create seg address="+str(address)+ "create seg na=" +str(next_address))
 
      sizer.current_segment_size += (next_address-address)
 
      #JLNEW
      ending_segment_address= address+read_instruction_data.size-1 

      print("segment size" + str(sizer.current_segment_size)) 
      print("ending_segment_address" + str(ending_segment_address)) 


      if (address >= addr.ending_address):
        return addr.ending_address


      # WE HAVE A VALID SEGMENT 
      new_segment[address] = read_instruction_data

      new_segment[address].starting_segment_address = addr.starting_segment_address
      new_segment[address].ending_segment_address = address
      starting_segment_address= new_segment[address].starting_segment_address


      final_segment_address = addr.starting_segment_address + sizer.current_segment_size   #total_size

      new_segment[addr.starting_segment_address].ending_segment_address = final_segment_address


      if(final_segment_address < addr.ending_address): 
          #some duplicates
          final_new_segment = new_segment
         
          final_new_segment[addr.starting_segment_address]['ending_segment_address'] =  new_segment[address].ending_segment_address 
        
          print("\n")
          # within current window or past final_address


      if (((sizer.current_segment_size+1) > sizer.window_segment_size) or (final_segment_address >= addr.ending_address)):

        final_segment_address = addr.starting_segment_address + sizer.current_segment_size
 
        #new_segment[addr.starting_segment_address].starting_segment_address = addr.starting_segment_address
        
        final_new_segment[addr.starting_segment_address]['starting_segment_address'] = addr.starting_segment_address
        final_new_segment[addr.starting_segment_address]['hashid'] = self.hash_segment(final_new_segment, sizer.current_segment_size)
        final_new_segment[addr.starting_segment_address]['size'] = addr.starting_segment_address + sizer.current_segment_size


        addr.next_all_address = addr.next_address
 

           
      # past ending address
      if (final_segment_address >= addr.ending_address):
        break 
      #print("addy="+str(address)+ "na=" +str(next_address))
      #JLNEW

      address = next_address
    

     
    print("CREATED NEW SEGMENT!")
    print("Starting segment address"+ str(starting_segment_address))
    print("segment ending_address" + str(ending_segment_address))
    print("--------------------")


    return final_new_segment


  def bump_segment_address_by_one(self, address):
    return address

  def update_found_segment(self, begining_address, address, segment):
    # TODO: code to get dictionary hash access
    global all_found_segments
    global all_found_addresses
    global all_only_found_addresses
 
    hashed=''
    size = sizer.current_segment_size
 
    hashed = self.hash_segment(segment,size)
    
    self.update_base_segment(address,hashed, size,segment)
    self.update_base_address(begining_address, address,hashed, size, segment) 
    self.update_only_base_address(address, hashed, size, segment)
 
    return # self.next_address

 
  
  def read_all_of_segment(self,address):
    global addr
    global all_found_segments
    read_hash = ''
    next_address = 0

    if (address >= addr.ending_address):
      return addr.ending_address

    found_segment={}
    found_segment = self.start_new_segment(address,found_segment) 

    if(found_segment[address]['starting_segment_address'] >= addr.ending_address): 
      return found_segment


    #if(self.next_address>0):
    #  address = self.next_address
   

    sizer.current_segment_size = 0
 
    while ((address+sizer.current_segment_size) < addr.ending_address and
         sizer.current_segment_size <= sizer.window_segment_size and
         sizer.window_segment_size <= sizer.maximum_segment_size):

      read_segment = self.create_segment(address)
 

      address = address 
                 
     
      if (address >= addr.ending_address):
          break

      read_hash = read_segment[addr.starting_segment_address]['hashid']

      print("current_segment_size=" + str(sizer.current_segment_size) )
      print("window_segment_size=" + str(sizer.window_segment_size) )
      print("maxiumum_segment_size=" + str(sizer.maximum_segment_size) )
      
      main_create_segment_address = address

      #fetch all instances of this particular segment throughout code space
      while ((address+sizer.current_segment_size) < addr.ending_address and
         sizer.current_segment_size <= sizer.window_segment_size and
         sizer.window_segment_size <= sizer.maximum_segment_size):
        print("SCAN SEGMENT:"+str(address))

        # should either give a working address or ending_address
        address = self.scan.all_instructions(read_segment, address)

        # JOHN: TODO!!!!!!! add end of address checking HERE!
        print("after scan address="+ str(address))
        if(address < addr.ending_address):
          

          # we found a copy, update
          print("\nupdate_found_segment address=" +str(address))
          print("\nupdate_found_segment next_all_address=" +str(addr.next_all_address))
          self.update_found_segment(addr.starting_segment_address, address, read_segment)   
        else:
          break 
        address = addr.next_all_address

      if (address >=addr.ending_address):
        break

      address = addr.next_address 
  
      print("addr.next_all_address=" + str(addr.next_all_address)) 
      print("seg address=" + str(address)) 
      print("mcreate_segment=" + str(main_create_segment_address))

      
      # address = main_create_segment_address 
    #main while for create_segment
 
    if(DEBUG_READ_ALL_OF_SEGMENT):
      print("FINISHED SEGMENT.") 

    return addr.next_all_address #self.next_address



  def update_only_base_address(self, address, hashed, size, segment):
    global all_only_found_segments

    counter = 1
    try: 
      counter=all_only_found_addresses[address][size]['count'] + 1

      print ("update_base_address counter:=" +str(counter))

      all_only_found_addresses[address][size]['count']=counter
      all_only_found_addresses[address][size]['addresses']= [address]
      all_only_found_addresses[address][size]['hashid'] = hashed
      all_only_found_addresses[address][size]['ending_segment_address'] = address
      all_only_found_addresses[address][size]['segment']= segment

    except(KeyError):
      all_only_found_addresses[address]={size: {}}
      #all_only_found_addresses[address][size]= {'segment':segment, 'count': counter, 'addresses':[address], 'hashid': hashed,'ending_segment_ddress': address }
 
      all_only_found_addresses[address][size]['count']=counter
      all_only_found_addresses[address][size]['addresses']= [address]
      all_only_found_addresses[address][size]['hashid'] = hashed
      all_only_found_addresses[address][size]['ending_segment_address'] = address
      all_only_found_addresses[address][size]['segment']= segment

  
    return 



  def update_base_address(self, begining_address, address, hashed, size,segment):
    global all_found_addresses

    counter = 1
    try: 
      counter=all_found_addresses[address][size]['count'] + 1

      print ("update_base_address counter:=" +str(counter))

      all_found_addresses[address][size]['count']=counter
      all_found_addresses[address][size]['addresses']= [address]
      all_found_addresses[address][size]['hashid'] = hashed
      all_found_addresses[address][size]['ending_segment_address'] = address
      all_found_addresses[address][size]['segment']= segment
      all_found_addresses[address][size]['start_address'] = begining_address
   
    except(KeyError):
      all_found_addresses[address]={size: {}}
   
      all_found_addresses[address][size]['count']=counter
      all_found_addresses[address][size]['addresses']= [address]
      all_found_addresses[address][size]['hashid'] = hashed
      all_found_addresses[address][size]['ending_segment_address'] = address
      all_found_addresses[address][size]['segment']= segment
      all_found_addresses[address][size]['start_address'] = begining_address
   
  
    return 


  def update_base_segment(self, address, hashed, size,segment):
    global all_found_segments

    counter = 1
    try: 
      counter = all_found_segments[hashed][size]['count']+1
      print ("base COUNTER1=" +str(counter))

      all_found_segments[hashed][size]['count'] = counter
     
      all_found_segments[hashed][size]['addresses'].append(address)
      all_found_segments[hashed][size]['hashid'] = hashed
      all_found_segments[hashed][size]['ending_segment_address'] = address
      all_found_segments[hashed][size]['segment']= segment
      all_found_segments[hashed][size]['address'] = address
    except(KeyError):
      all_found_segments[hashed]={size: {}}
    
      all_found_segments[hashed][size]['count'] = counter
      all_found_segments[hashed][size]['addresses']= [address]
      
      #all_found_segments[hashed][size]['addresses'].append(address)
      all_found_segments[hashed][size]['hashid'] = hashed
      all_found_segments[hashed][size]['ending_segment_address'] = address
      all_found_segments[hashed][size]['segment']= segment
      all_found_segments[hashed][size]['address'] = address
 
  
    return 


  def report(self):
    #print("report for all segments:" + segment)
    total_hash = ''
    for (key,val) in self.items():

      if(DEBUG_REPORT):
        print("rep:" +str(val['segment'].address) + ' ' + val['segment'].label + " DATA: " + val['segment'].data )



def generate_report(segment):
  #JKLO import overlap 
  w_size = 1
 
  # reference: all_found_segments[hashed][size]['count']
  #print("FOUND original address: -"+ str(read_segment[j[z-1]]['segment'].address)+ "- '"+ cur_inst.label.strip() + " " + cur_inst.data.strip()  + "' @ adress "+ str(start_all_address) + " !!!!!!!!!!!!!!!!!!!!")
          
 
  for got_address,got_seg in segment.items():
    #print("found node at " + format(got_address,'02x') +" decimal=" +str(got_address)) 
    #print("found original segement" +  "node at " + format(got_address,'02x') +" decimal=" +str(got_address)) 
 

    for i,j in got_seg.items():
      # sys.stdout.write (" size=" +str(i))
      #print("found original segment " + str(segment[got_address][i]['address']) + " node at " + format(got_address,'02x') +" decimal=" +str(got_address)) 
      print("found original segment " + str(segment[got_address][i]['start_address']) + " node at " + format(got_address,'04x') +" decimal=" +str(got_address) + " size=" +str(i)) 
 
   
      print("seg count=" + str(segment[got_address][i]['count']))
          
      if (segment[got_address][i]['count'] > 1):
        print(" Segment HASH=" + str(segment[got_address][i]['hashid']))
        #print("i="+str(i)  + " j=" + str(j))
        #if (i!='segment'):
        for k,m in j.items(): 
          print("k="+str(k) + " m=" + str(m))
          if (k == 'segment'):
            pass #print("m[0]="+ str( m[0]) )
      print("")






# copyright (c) 2019 By John Lutz AKA John Talent

#1) create_block : scan. hash exist? yes store segment+ hash[level] is open, level++
#2)                   no, close level[level]
#3) block_nonoverallpings =  determine_block_nonoverlappings(block)  # (traverse overlappings)
#4) largest_block = select_largest_bloct_nonoverlappings(block_nonoveralappings) #( "" )
#5) print (largest_no_block) ... done!

# overall: to build block
#while address++
# while size++
#  parent_addr/size ++              #build up a new addr for each 6510 source file
#
#  for overlapped: 
#    while parent_addr/size++
#      if not exists parent_addr/size 
#        add latest parent_add/size  #builds up a new size for every addr
#      set overlapped 
#
#  for nonoverlapped:
#    while_parent_addr/size++  # wind down overlapping segments
#       if no longer overlapped  #make non overlapped
#         remove parent context if no longer overlapped 
#       while parent_addr
#          if overlapped
#            get largest
#            test             
#
#       while parent_addr
#          if overlapped   
#            assign new largest
#
#  save parts of block that haven't already been saved
#

class largest_block:
    # TODO assign class to rest of code
    current_largest_block = 0
    prev_size = 0
    start_largest_block = 0
    largest_overlapper={0:{'size':0,'addr':0}}
 

# GET LARGEST ADDRESS SIZE # 2
# params= array, block 
def get_assign_large_overlapper_blocks(parent_overlap_addr, parent_overlap_size, addr, size, block):
    # TODO block : small overlap -> large nonoverlap -> small overlap = ln gets selected: ADD THIS CASE
    # TODO TODO!!! for each block (ends in one largest), keep permanent and != pass check to keep alive
    # if reaching end of code or no overlapping at all, choose highest for that 'BLOCK', keep as above.
    # this will ALWAYS have a parent_overlap_addr of at least 1 (array #: 0)
    global largest_block
    for bindex, block_id in enumerate(block): 
        for index, current_parent in enumerate(parent_overlap_addr): #TODO was r_
            print("index="+str(index) + " current_parent=" +str(current_parent)+ " parent_overlap_size=" +str(parent_overlap_size))
            current_size = parent_overlap_size[index]

            if ((addr >= current_parent+current_size) or 
                (addr+size >= current_parent)): # was addr-size
                # continue from current_largest_block's last largest
                # each unique largest overlapping block has it's own current_largest_block.
                for icurrent_largest_block in range(largest_block.start_largest_block, len(largest_block.largest_overlapper)):
                    try:    
                        print("icurrent_lb="+str(icurrent_largest_block))
                        print("lb.lo=" + str(largest_block.largest_overlapper[icurrent_largest_block]))
                    except(KeyError):
                        largest_block.largest_overlapper={icurrent_largest_block: {'addr':0, 'size':0}}
                        print("KeyError icurrent_lb="+str(icurrent_largest_block))
                        print("KeyError lb.lo=" + str(largest_block.largest_overlapper[icurrent_largest_block]))
     
                    # Get min of parent_overlap, this is the block start
                    if('size' in largest_block.largest_overlapper[icurrent_largest_block]):
                         if ( (block[block_id][current_parent][current_size]['size'] > largest_block.largest_overlapper[icurrent_largest_block]['size']) and (block[block_id][current_parent][current_size]['overlapped'] == True) ):
                            largest_block.largest_overlapper[icurrent_largest_block] = {'addr': block[block_id][current_parent][current_size]['addr'] ,'size': block[block_id][current_parent][current_size]['size'] }

                            icurrent_largest_block+=1

    if(icurrent_largest_block > 0):
        largest_block.current_largest_block = icurrent_largest_block - 1

    return largest_block.largest_overlapper[largest_block.current_largest_block]  # returns addr/size structure


def get_largest_overlapper_block():
    found_largest={}
    found_largest['size'] = 0
    found_largest['addr'] = 0

    print("in get_largest: largest_block.largest_overlapper"+ str(largest_block.largest_overlapper))
    for icurrent_largest_block in range(largest_block.start_largest_block, len(largest_block.largest_overlapper)):
        
        cur_addr = largest_block.largest_overlapper[icurrent_largest_block]['addr'] 
        size     = largest_block.largest_overlapper[icurrent_largest_block]['size'] 
        if (found_largest['size'] < size):
            found_largest['addr'] = cur_addr
            found_largest['size'] = size


    return found_largest  # returns addr/size structure


def is_Just_Lost_A_Parent(address_range, block):
    global largest_block

    print("lbps=" + str(largest_block.prev_size)) 
    if (len(address_range) < largest_block.prev_size):
        return True
    else:
        print("SIMPSONS did it! address_range:"+ str(len(address_range)))
        largest_block.prev_size = len(address_range)
        return False



def create_block_hierarchy(address):
    #"" creates block of overlapping and non overlapping segments ""
    global largest_block
    global sizer
    global all_only_found_addresses
    global all_found_addresses
    global all_found_segments
    global addr
    global block_id
    global largest_found_block
    level=0
    plevel=0
    overlapped = False
    nsize = 0
    cur_addr = addr.begining_address
    #print("before scan")
    scan = Scan()

    # simple block of address to size

    block={}
    found_hash="X0X0"
    block_id=0
    # what the current overlapper is, it's addr and size
    largest_overlapper_addr = 0
    largest_overlapper_size = 0

    largest_found_block={}
    largest_found_block[block_id]={}
    largest_found_block[block_id]['size'] = 0
    largest_found_block[block_id]['addr'] = 0


    # these are multiple values in arrays that describe what parent block this block falls under
    parent_overlap_addr = []
    parent_overlap_size = []
    parent_overlap_deleted=[]
    original_parent_overlap_addr = []
    original_parent_overlap_size = []

    block_id=0 # 0 is for all non-overlapping block

    original_parent_overlap_addr=[]

    bFirstLostParent = True
    bIsLargestAndDone = False
                 
        #all overlapped are not set here 
    while (cur_addr < addr.ending_address):

        read_instruction_data = scan.one_instruction(cur_addr)
        if (read_instruction_data.address >= addr.ending_address):
          return addr.ending_address


        print("read_instruction_data: "+ str(read_instruction_data.address))
        #NOTE: TODO shold have size in addition to address for hashid. both in main prg and here 
       
        found_hash = None 
        try:
            found_hash = all_only_found_addresses[read_instruction_data.address]['hashid'] 
        except(KeyError):
            print("Key Error on found_hash addr="+str(read_instruction_data.address))
            cur_addr = read_instruction_data.next_address
            continue

        if (found_hash != None ): 
            print("In hash!") 
            print("check all_found_segments (RH): " + str(all_only_found_addresses[read_instruction_data.address]['hashid'])) 
          
            cur_addr = read_instruction_data.address

            #HANDLES ALL ADDRESSES UP TILL NOW

            
            #/addr = addressess  
            #   CREATE HIERACHY OF OVERLAPPING/NONOVERLAPPING BLOCKS
            #   ADDRESS/SIZE/SIZE,etc

            #HANDLES ALL ADDRESSES UP TILL NOW
            # TODO JKL raise your own custom error!
            for size in all_found_addresses[cur_addr]:
                parent_overlap_addr.append(cur_addr)
                original_parent_overlap_addr = parent_overlap_addr.copy()

                parent_overlap_size.append(size)
                original_parent_overlap_size = list(parent_overlap_size) #HANDLES ALL SIZES FOR ABOVE ADDRESSES UP TILL NOW

                parent_overlap_deleted.append(False)


                print("size=" +str(size))
                try: 
                    if (block_id not in block):
                        block[block_id]={}
                    if (cur_addr not in block[block_id]):
                        block[block_id][cur_addr]={}

                    block[block_id][cur_addr].update({size: {'count': 1, 'overlapped': True, 'addresses':[cur_addr], 'addr':cur_addr, 'size':size, 'parent_overlap_size':parent_overlap_size,'parent_overlap_addr':parent_overlap_addr, 'parent_overlap_deleted':parent_overlap_deleted}} )
                except (KeyError):
                    print("could not assign new size to block[cur_addr]!")

                    block.update({block_id:{cur_addr:{size: {'count': 1, 'overlapped': True, 'addresses':[cur_addr], 'addr':cur_addr, 'size':size, 'parent_overlap_size':[],'parent_overlap_addr':[],'parent_overlap_deleted':[] }}}})
                print("after_RAISE") 

                index=-1
                # IF FOUND OVERLAPPED, ADD OVERLAPPED
                # ADDED ABOVE ONE AT A TIME, ITERATION UNTIL ALL REMOVED BELOW
                for lindex, n_parent_overlap_addr in enumerate(original_parent_overlap_addr):
                 
                    print("add overlap array! index="+str(lindex)) 
                    n_parent_overlap_size = original_parent_overlap_size[lindex]
                      
                    print("lindex="+str(lindex)+"n_poa:" + str(n_parent_overlap_addr)+ " npos:" +str(n_parent_overlap_size))
                    if ((cur_addr >= parent_overlap_addr[lindex]+n_parent_overlap_size) or 
                        (cur_addr+size >= n_parent_overlap_addr)): # was addr-size
 
                        index+=1
                        print("FOUND AN OVERLAP!#!#!  cur_addr="+str(cur_addr)) 
                        # create new subblock
                        try: 
                            block[block_id][n_parent_overlap_addr][n_parent_overlap_size].update({'overlapped': True})
                            print ("just SET overlapped!")
                            # TODO maintain index seperate of for loop
                            # TODO: if already exists, don't add! Allow multiple same overlap addr, but not with size!
                            if (parent_overlap_addr[index] not in block[block_id][cur_addr][size]['parent_overlap_addr'][n_parent_overlap_addr]):

                                if (parent_overlap_size[index] not in block[block_id][cur_addr][size]['parent_overlap_size'][parent_overlap_size[index]]):

                                    block[block_id][cur_addr][size]['parent_overlap_addr'].append( parent_overlap_addr[index] ) # always in order so okay
                                    block[block_id][cur_addr][size]['parent_overlap_size'].append( parent_overlap_size[index] ) # ""
                                    #for deleteing nondestructively

                                    block[block_id][cur_addr][size]['parent_overlap_deleted'].append(index) 
                                    block[block_id][cur_addr][size]['parent_overlap_deleted'][index]= False
                                    parent_overlap_deleted.append(index)
                                    parent_overlap_deleted[index]=False
 
                        except(KeyError):
                            print("Keyerror: poa " +str( parent_overlap_addr[index]))
                            print("Kererror: block_addr_size: " +str(block[block_id][cur_addr][size]['parent_overlap_addr']))
                            block[block_id][cur_addr][size]['parent_overlap_addr'].append( parent_overlap_addr[index])
                            block[block_id][cur_addr][size]['parent_overlap_size'].append( parent_overlap_size[index])
                        except(IndexError):
                            #TODO JOHN NEEDS AN UPDATE OF BLOCK OF PARENT_OVERLAP (from block_cur)
                            print("indexError: AFTER append: Block: @ "+str(cur_addr)+ " " + str(block[block_id][cur_addr]))
                    else:
                        block[block_id][n_parent_overlap_addr][n_parent_overlap_size]['overlapped'] = False
                        block_id = block_id +1

 
                # CHECK AND PROCESS BELOW NO MATTER WHAT (IRREGARDLESS TO PREVIOUS ADDRESS)
                # make a copy so iteration isn't balls-to-the-wall

                copy_parent_overlap_addr = list(block[block_id][cur_addr][size]['parent_overlap_addr'])
                copy_parent_overlap_size = list(block[block_id][cur_addr][size]['parent_overlap_size'])

                clone_parent_overlap_addr = list(block[block_id][cur_addr][size]['parent_overlap_addr'])
                index=-1

                print("DETERMINE IS SHRINKING poa:" + str(block[block_id][cur_addr][size]['parent_overlap_addr']))
                while (True): 
                    index+=1
                    # Is parent_overlap_addr shrinking?
                    if ( is_Just_Lost_A_Parent(parent_overlap_addr, block) ):
                        print("IS SHRINKING!!!!!")
                        if (bFirstLostParent == True):
                            #critical, assigns global to beginning of this block
                            largest_block.start_largest_block = largest_block.current_largest_block
                            bFirstLostParent = False

                    print("current_largest_block=" + str(largest_block.current_largest_block)) 
                    #   yes: GET LAST LARGEST
                    get_assign_large_overlapper_blocks(parent_overlap_addr, parent_overlap_size, cur_addr, size, block)

                    # if reaching end of code or no overlapping at all, choose highest for that 'BLOCK', keep as above.
                    
                    try:
                        block[block_id][cur_addr][size]['parent_overlap_deleted'][index]=True
                    except (IndexError):
                        break
                    try: 
                        clone_parent_overlap_addr.pop(index)
                        
                    except(IndexError):
                        break

                    bSetLargest = True
                    for bindice, content in enumerate(clone_parent_overlap_addr):
                        if (content== False):
                            bSetLargest = False
                        
                    # All overlapping's are processed, we deleted them all: time to update totals
                    if (bSetLargest): # and len(clone_parent_overlap_addr) == 0):
                        print("Setting Largest")
                        largest_block_found = get_largest_overlapper_block()
                        print("current_largest_block=" + str(largest_block.current_largest_block)) 
                     
                        print("largest_found_block=" + str(block_id))
                        if (largest_overlapper_addr not in largest_found_block[block_id]):
                            largest_found_block[block_id]={}

                        largest_found_block[block_id]['largest_overlapper_addr'] = largest_block_found['addr']
                        largest_found_block[block_id]['largest_overlapper_size'] = largest_block_found['size']
                    
                        bFirstLostParent = True
       
                # continue for each size [from] (adjacent to for tc_parent_addr...)
                segment = all_found_addresses[cur_addr][size]['segment']

                #NICELY ADD RECORD WITH PROPER CONTEXT. CONTEXT IS KEY!
                if ('baddress' not in block[block_id][cur_addr][size]):
                    block[block_id][cur_addr][size]['baddress'] = read_instruction_data.address

                if ('size' not in block[block_id][cur_addr][size]):
                    block[block_id][cur_addr][size]['size'] = size

                if ('segment' not in block[block_id][cur_addr][size]):
                    block[block_id][cur_addr][size]['segment'] =segment

                if ('parent_overlap_addr' not in block[block_id][cur_addr][size]):
                    block[block_id][cur_addr][size]['parent_overlap_addr']=parent_overlap_addr 

                if ('parent_overlap_size' not in block[block_id][cur_addr][size]):
                    block[block_id][cur_addr][size]['parent_overlap_size']= parent_overlap_size

                if ('overlapped' not in block[block_id][cur_addr][size]):
                    block[block_id][cur_addr][size]['overlapped']=overlapped

                if ('largest_overlapper_addr' not in block[block_id][cur_addr][size]):
                    block[block_id][cur_addr][size]['largest_overlapper_addr'] = largest_overlapper_addr

                if ('largest_overlapper_size' not in block[block_id][cur_addr][size]):
                    block[block_id][cur_addr][size]['largest_overlapper_size'] =largest_overlapper_size
                        # for match

        cur_addr = read_instruction_data.next_address
    return block



    
def select_largest_blocks(block):
    plevel=0
    level=0
    largest_block={}

    #block.update({cur_addr:{size: {'count': 1, 'overlapped': True, 'addresses':[cur_addr], 'addr':cur_addr, 'size':size, 'parent_overlap_size':[],'parent_overlap_addr':[],'parent_overlap_deleted':[] }}})
 
    for block_id, whole_item in block.items():

        for current_address, whole_block in block[block_id].items():
            print("found_node at:" +str(current_address)) # + "block " + str(whole_block) )
 
            for current_size, whole_size in block[block_id][current_address].items():
                print ("current_size="+ str(current_size)+ " block[cur,size]:" + str(block[block_id][current_address][current_size])  ) 
                if (block[block_id][current_address][current_size]['overlapped']==False): # HANDLE NON-OVERLAPPING 
                    # get all non-overlappers
                    largest_block.update({block_id:{current_address:{current_size:   block[block_id][current_address][current_size]}}})

                # only select the largest overlappers
                elif (block[block_id][current_address][current_size]['largest_overlapper_addr']>0):
                    print(" found overlapping!!! ")
                    largest_block.update({block_id:{current_address:{current_size:  block[block_id][current_address][current_size]}}})


    # (now you have defragmented BIGGEST segments)
    return largest_block

def report_all_blocks(block):
    global largest_found_block
    print("report all blocks!!!!" +str( largest_found_block))
    #r block_id, whole_item in largest_found_block.items():
    #  for current_address, whole_block in block[block_id].items():
    #        for current_size , whole_size in block[block_id][current_address].items():
    #            print("addr=" + str(current_address) + "size=" + str(current_size))
    print("done!")

#def main():
#    has_nonoverlapped_blocks = create_block_hierarchy(0)
#    report_this_block = select_largest_blocks(has_nonoverlapped_blocks)
#    report_all_blocks(report_this_block)


def invoke_cosmic_cruncher():
  from assem import array_aid
  global addr
  global sizer
  global largest_block
  #global all_found_segments
  global array_aid
 
  size=0
  #addr = Address()
  segment = Segment(0,0,0)
  addr.begining_address = 768 # TODO CHANGE ME!!!!!!!!!!!!24576
  addr.starting_address = addr.begining_address

  address = addr.starting_address
  sizer.current_segment_size = 0 #for inner loops
  sizer.window_segment_size = 7
 
  segment_size = sizer.current_segment_size
  all_found_segments={segment_size: {'segment':segment, 'count': 1, 'addresses':[address]}}
  all_found_addresses[0]={}

  all_only_found_segments={segment_size: {'segment':segment, 'count': 1, 'addresses':[address]}}
  all_only_found_addresses[0]={}


  largest_block.largest_overlapper={9:{'size':0,'addr':0}}
 
  #all_found_addresses[0]= {'segment':segment, 'count': 1, 'addresses':[0], segment_size: [] }
 
  
  #all_found_segments['0'] = {'segment':Segment(0,0,0)}
  #all_found_segments['0']['segment'].count = 0

  #all_found_segments = { 'X': {'starting_segment_address': address, 'segment': Segment, 'hashid': 'X1'}}
  #all_found_segments['X']['segment'].count = 0



  find_all_segments = Segment(0,addr.begining_address,1)

  i = addr.begining_address
  if (addr.ending_address < 1):
    addr.ending_address = 128000
 
  while True:
    try:
      cur_inst = find_all_segments.one_instruction(i)
      i += cur_inst.size
    except KeyError:
      #print("i=" + str(i))
      addr.ending_byte_address = i
      i -= cur_inst.size-1
      break 
  addr.ending_address = i+1
  print("instruction ending_address is: " + str(addr.ending_address))

  find_all_segments.next_address = addr.starting_address
 
  while (address+sizer.current_segment_size < addr.ending_address and
         sizer.current_segment_size < sizer.window_segment_size and
         sizer.window_segment_size < sizer.maximum_segment_size):

    sizer.current_segment_size = 0
    find_all_segments.next_address = addr.starting_address
    address = addr.starting_address
     
    while (((address+sizer.current_segment_size) < addr.ending_address) and (address < addr.ending_address) and ( sizer.current_segment_size <= sizer.window_segment_size)):
      #read all segments of window size +1
      print("\n")
      print("current_segment_size=" + str(sizer.current_segment_size))
      print("window_segment_size=" + str(sizer.window_segment_size))
      print("find_all_segments.next_address=" +str( find_all_segments.next_address))
      print("---------------------------------------------------------")
      address = find_all_segments.read_all_of_segment(find_all_segments.next_address)
      #JLNEW might need to make it bump by size
      #sizer.current_segment_size += address
 
      sizer.current_segment_size +=1  
    sizer.window_segment_size += 1
  

  total_hash = ''

  generate_report(all_found_addresses)

  ##REMOVE OVERLAP has_nonoverlapped_blocks = create_block_hierarchy(0)
  ##REMOVE OVERLAP report_this_block = select_largest_blocks(has_nonoverlapped_blocks)
  ##REMOVE OVERLAP report_all_blocks(report_this_block)

  print("All Done!")



if __name__ == '__main__':
    print ("")
    print ("This is a python module, it's not a program.")
    print ("This module is part of the sbasm package.")
    print ("Run sbasm instead.")
    print ("")

