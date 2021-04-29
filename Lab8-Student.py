#### run this program as 
### sudo mn --topo single,3 --controller remote --mac --arp

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER,CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet,arp,ipv4
from ryu.lib.packet import ether_types
from ryu.lib.dpid import dpid_to_str,str_to_dpid
from ryu.lib import hub

class SimpleL2Switch(app_manager.RyuApp): #creating a simple switch as a Ryu App
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	#####     SECTION -1 #################

	def __init__(self, *args, **kwargs):
		super(SimpleL2Switch, self).__init__(*args, **kwargs) # simpleL2switch is a child of Ryu App.
		self.mac_to_port = {} #{port1:[mac1,ip1],port2:[mac2,ip2]...},...} #to store the details of switch and connected hosts IP and mac address
   	 
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, event): # this method handles switch feature requests and we install initial flow to forward all the packets to the controller incase of a table miss.
		print (" *** in feature handler *** ")
		............................................................. # send to the controller
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, event):
		pkt = packet.Packet(data=event.msg.data) # creating a packet with msg's data as payload
		eth = pkt.get_protocols(ethernet.ethernet)[0] # fetching ethernet dataframe
		if eth.ethertype == ether_types.ETH_TYPE_ARP:#handling ARP requests # ARP packet is ethernet dataframe's payload. Ethernet frame has type from as ETH_TYPE_ARP, if true then handle ARP
			
			............................................................. # call method to handle ARP packets
		elif eth.ethertype == ether_types.ETH_TYPE_IP: #handle IP packet.
			
			............................................................. #call method to handle IP packet


	#########   SECTION -2 ###############

	def handle_ARP(self,event): # handle ARP packets
		datapath = event.msg.datapath # datapath connection
		ofproto = datapath.ofproto #ofproto of the datapath
		in_port = event.msg.match['in_port'] # port through which the switch recieved this packet
		parser = datapath.ofproto_parser 
		pkt = packet.Packet(data=event.msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0] # fetching ethernet dataframe

		arp_pkt = pkt.get_protocol(arp.arp) #.............................................................
		self.mac_to_port[in_port] = [arp_pkt.src_mac,arp_pkt.src_ip] # .............................................................
		out_port = self.check_mactable(ofproto,'arp',arp_pkt.dst_mac) # .............................................................
		actions = [parser.OFPActionOutput(out_port)] # .............................................................
		match = self.simplematch(parser,eth.src,eth.dst,in_port) # .............................................................
		self.add_flow(datapath, 1, match, actions, buffer_id=None) # .............................................................


	def handle_IP(self,event): #handle IP packets
		datapath = event.msg.datapath # datapath connection
		ofproto = datapath.ofproto #ofproto of the datapath
		in_port = event.msg.match['in_port'] # port through which the switch received this packet
		parser = datapath.ofproto_parser
		pkt = packet.Packet(data=event.msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0] # .............................................................

		ip_pkt = pkt.get_protocol(ipv4.ipv4) #extract Ip payload

		out_port = self.check_mactable(ofproto,'ip',ip_pkt.dst) # .............................................................
		match = self.simplematch(parser,eth.src,eth.dst,in_port) # .............................................................
		actions = [parser.OFPActionOutput(port=out_port)] # ...................................................................
		if event.msg.buffer_id != ofproto.OFP_NO_BUFFER:
			self.add_flow(datapath, 1, match, actions, event.msg.buffer_id) # .............................................................
		else:
			self.add_flow(datapath, 1, match, actions)


	def check_mactable(self,ofproto,caller,para): # to check if an mac addr or IP addr exists in mac table
		if caller == 'arp': # if the calling function is arp, then check mac address
			for p in self.mac_to_port:
				if self.mac_to_port[p][0] == para: #[p][0] .............................................................
					return p # return p as outport # if found return
		elif caller == 'ip': # if calling function is ip , then check ip addr
			for p in self.mac_to_port:
				if self.mac_to_port[p][1] == para: #.............................................................
					return p  # return corresponding port
		return ofproto.OFPP_FLOOD # if no port is found .............................................................




	def sendto_controller(self,event): # initial installation of table miss flow 
		datapath = event.msg.datapath #.
		ofproto = datapath.ofproto #.
		parser = datapath.ofproto_parser #.
		match = parser.OFPMatch() #.
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)] # .......................................
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
		mod = parser.OFPFlowMod(datapath=datapath,priority=0,match=match,instructions=inst)
		datapath.send_msg(mod)

	def add_flow(self, datapath, priority, match, actions, buffer_id=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		idle_timeout=45 # idle-timeout set to flush out flows
		hard_timeout=45
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)] #forming instructions
		if buffer_id:
			mod = parser.OFPFlowMod(datapath=datapath,buffer_id=buffer_id,priority=priority,idle_timeout=idle_timeout,hard_timeout = hard_timeout, match=match,instructions=inst)
		else:
			mod = parser.OFPFlowMod(datapath=datapath,priority=priority,match=match,idle_timeout=idle_timeout,hard_timeout = hard_timeout,instructions=inst)
		self.logger.info("added flow for %s",mod)
		datapath.send_msg(mod)

	#### request the packet to be forwarded onto a specific port from the switch ###
	def switchport_out(self,pkt,datapath,port): #.
		'''accept raw data , serialise it and packetout from a OF switch ''' #
		ofproto = datapath.ofproto #.
		parser = datapath.ofproto_parser #.
		pkt.serialize() #. serialise packet  (ie convert raw data)
		self.logger.info("packet-out %s" %(pkt,)) #.
		data = pkt.data #.
		actions = [parser.OFPActionOutput(port=port)] #.
		out = parser.OFPPacketOut(datapath = 		datapath,buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER,actions=actions,data=data) #.
		datapath.send_msg(out) #.

	def simplematch(self,parser,src,dst,in_port):
		match = parser.OFPMatch(in_port=in_port,eth_dst=dst,eth_src=src) #
		return match    





