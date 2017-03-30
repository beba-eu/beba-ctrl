'''
2. Load balancer
Configure a load balancer function that assigns TCP connections to two web servers, in a round-robin fashion 

Step-by-step Simulation Startup
1) Launch server load balancing controller application in Mininet by typing the following command:
$ ryu-manager ~/beba-ctrl/ryu/app/beba/IPTablesCase2.py

2) Start Mininet with a custom topology:
$ sudo python start_mn_mytopo_IPTABLES

3) Write inside the terminals of Mininet the following commands :
$ xterm h1 h3 h4

4) Write inside the terminals of h3-h4 the following commands :
h3# nc -lvp 80
h4# nc -lvp 80

5) Write inside the terminals of h1 the following commands :
h1# nc -v 1.0.0.1 80

First connection 	 h4
Second connection 	 h3
Third connection 	 h4
.
.
.

'''


import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser

import ryu.ofproto.beba_v1_0  as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser 

LOG = logging.getLogger('app.openstate.evolution')

DMZ_PORT = 2
LAN_PORT = 3
INTERNET_PORT = 1


class OpenStateEvolution(app_manager.RyuApp):

	def __init__(self, *args, **kwargs):
		super(OpenStateEvolution, self).__init__(*args, **kwargs)

	def add_flow(self, datapath, table_id, priority, match, actions):
		if len(actions) > 0:
			inst = [ofparser.OFPInstructionActions(
					ofproto.OFPIT_APPLY_ACTIONS, actions)]
		else:
			inst = []
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table_id,
								priority=priority, match=match, instructions=inst)
		datapath.send_msg(mod)



	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, event):

		""" Switche sent his features, check if OpenState supported """
		msg = event.msg
		datapath = msg.datapath

		LOG.info("Configuring switch %d..." % datapath.id)

		if datapath.id == 2:
			self.install_forward(datapath)
		else:		
			self.function_load_balancer(datapath)



	'''########################################################################################################################################################## 
	############################################################################################################################################################# 
	##########################################################                            ####################################################################### 
	##########################################################   FUNCTION LOAD BALANCER   ####################################################################### 
	##########################################################                            ####################################################################### 
	##########################################################################################################################################################''' 


	def function_load_balancer(self, datapath):

		""" Tab0 """
		""" Set table 0 as stateful """	
		req = bebaparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=0,
				stateful=1)
		datapath.send_msg(req)

		""" Set table 3 translate """
		req = bebaparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=3,
				stateful=1)
		datapath.send_msg(req)


	############################### LOOKUP/UPDATE ###################################

		""" Tab0 """
		""" Set lookup extractor = {BiFlow} """ 
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_IPV4_SRC, ofproto.OXM_OF_IPV4_DST,
						ofproto.OXM_OF_TCP_SRC, ofproto.OXM_OF_TCP_DST],
				table_id=0,
				biflow = 1)
		datapath.send_msg(req)

		""" Set lookup extractor = {BiFlow} """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_IPV4_SRC, ofproto.OXM_OF_IPV4_DST,
						ofproto.OXM_OF_TCP_SRC, ofproto.OXM_OF_TCP_DST],
				table_id=0,
				biflow = 1)
		datapath.send_msg(req)


		""" Tab3 """
		""" Set lookup extractor = {OXM_OF_IPV4_SRC, OXM_OF_TCP_SRC} """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_IPV4_SRC, ofproto.OXM_OF_TCP_SRC],
				table_id=3)
		datapath.send_msg(req)

		""" Set update extractor = {OXM_OF_IPV4_SRC, OXM_OF_TCP_SRC} """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_IPV4_SRC, ofproto.OXM_OF_TCP_SRC],
				table_id=3)
		datapath.send_msg(req)


		########################### SET GD DATA VARIABLE TAB 0 ############################################


		''' GD[0] = 0''' 
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=0,
				value=0)				
		datapath.send_msg(req)

		''' GD[1] = 0 '''
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=0,
				value=0)				
		datapath.send_msg(req)

		########################### SET GD E HF DATA VARIABLE TAB 3 ############################################


		''' GD[0] = 0''' 
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=3,
				global_data_variable_id=0,
				value=0)				
		datapath.send_msg(req)

		''' GD[1] = LAN_DUE 10.0.0.2 hexadecimal''' 
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=3,
				global_data_variable_id=1,
				value=0x0200000a)				
		datapath.send_msg(req)

		''' GD[2] = LAN_TRE 10.0.0.3 hexadecimal''' 
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=3,
				global_data_variable_id=2,
				value=0x0300000a)				
		datapath.send_msg(req)

		# non serve
		''' GD[3] = PORT 80 ''' 
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=3,
				global_data_variable_id=3,
				# value=0xa000003)
				value=0x5000)				
		datapath.send_msg(req)


		################################# RULES ############################################

		''' #######################  TAB 0  '''

		# Line ARP
		match = ofparser.OFPMatch(eth_type=0x0806)
		actions = [ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=100, match=match, instructions=inst)
		datapath.send_msg(mod)


		# Line 7
		match = ofparser.OFPMatch(state=0, in_port=INTERNET_PORT, eth_type=0x0800, ipv4_dst='1.0.0.1', ip_proto=6, tcp_dst=80)
		actions = [bebaparser.OFPExpActionSetState(state=1, table_id=0),
				   bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_gd_id=0, operand_1_gd_id=0, operand_2_cost=1),
				   bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_GLOBAL_DATA_VAR,src_id=0,dst_field=ofproto.OXM_OF_METADATA)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(3)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=93, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 8
		match = ofparser.OFPMatch(state=1, in_port=INTERNET_PORT, eth_type=0x0800, ipv4_dst='1.0.0.1', ip_proto=6, tcp_dst=80)
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(3)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=92, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 9
		match = ofparser.OFPMatch(state=0, in_port=LAN_PORT, eth_type=0x0800, ipv4_src='10.0.0.2', ip_proto=6, tcp_src=80)
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=91, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 10
		match = ofparser.OFPMatch(state=0, in_port=LAN_PORT, eth_type=0x0800, ipv4_src='10.0.0.3', ip_proto=6, tcp_src=80)
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=90, match=match, instructions=inst)
		datapath.send_msg(mod)



		''' #######################  TAB 3 translate ''' 

		# Line 0
		# ip.dst = 10.0.0.2 
		# tcp.dst = 80
		# 10.0.0.2 -> R0 => 10.0.0.2 -> FD[0] => FD[0] = GD[0] + 10.0.0.2 => 0 + 10.0.0.2
		# 80 -> R1 		 => 80 -> FD[1] 	  => GD[0] + 80 			  => 0 + 80
		match = ofparser.OFPMatch(state=0, in_port=INTERNET_PORT, metadata=(0, 0x000000001), eth_type=0x0800, ip_proto=6)
		actions = [bebaparser.OFPExpActionSetState(state=1, table_id=3),
				   ofparser.OFPActionSetField(ipv4_dst='10.0.0.2'),
				   ofparser.OFPActionSetField(tcp_dst=80),
				   # tolto per test
				   bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM, output_fd_id=0, operand_1_gd_id=1, operand_2_cost=0),
				   bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM, output_fd_id=1, operand_1_gd_id=0, operand_2_cost=80)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=3,
								priority=100, match=match, instructions=inst)
		datapath.send_msg(mod)


		# Line 1
		# ip.dst = 10.0.0.3 
		# tcp.dst = 80
		# 10.0.0.3 -> R0 => 10.0.0.3 -> FD[0] => FD[0] = GD[0] + 10.0.0.3 => 0 + 10.0.0.3
		# 80 -> R1 		 => 80 -> FD[1] 	  => GD[0] + 80 			  => 0 + 80
		match = ofparser.OFPMatch(state=0, in_port=INTERNET_PORT, metadata=(1, 0x000000001), eth_type=0x0800, ip_proto=6)
		actions = [bebaparser.OFPExpActionSetState(state=1, table_id=3),
				   ofparser.OFPActionSetField(ipv4_dst='10.0.0.3'),
				   ofparser.OFPActionSetField(tcp_dst=80),
				   # tolto per test
				   bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM, output_fd_id=0, operand_1_gd_id=2, operand_2_cost=0),
				   bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM, output_fd_id=1, operand_1_gd_id=0, operand_2_cost=80)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=3,
								priority=99, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 2 
		# ip.dst = R0 => IPV4_DST = FD[0]
		# tcp.dst = R1 => TCP_DST = FD[1]
		match = ofparser.OFPMatch(state=1, in_port=INTERNET_PORT)
		actions = [bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_FLOW_DATA_VAR,src_id=0,dst_field=ofproto.OXM_OF_IPV4_DST),
				   bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_FLOW_DATA_VAR,src_id=1,dst_field=ofproto.OXM_OF_TCP_DST)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=3,
								priority=98, match=match, instructions=inst)
		datapath.send_msg(mod)


		''' #######################  TAB 4 forward '''

		# Line 2
		match = ofparser.OFPMatch(eth_type=0x0800, ipv4_dst='8.0.0.2')
		actions = [ofparser.OFPActionSetField(eth_dst="00:00:00:00:00:02"),
					ofparser.OFPActionOutput(DMZ_PORT)]
		self.add_flow(datapath=datapath, table_id=4, priority=98,
						match=match, actions=actions)


		# Line 3 
		match = ofparser.OFPMatch(eth_type=0x0800, ipv4_dst='10.0.0.2')
		actions = [ofparser.OFPActionSetField(eth_dst="00:00:00:00:00:03"),
					ofparser.OFPActionOutput(LAN_PORT)]
		self.add_flow(datapath=datapath, table_id=4, priority=97,
						match=match, actions=actions)

		# Line 3 BIS 
		match = ofparser.OFPMatch(eth_type=0x0800, ipv4_dst='10.0.0.3')
		actions = [ofparser.OFPActionSetField(eth_dst="00:00:00:00:00:04"),
					ofparser.OFPActionOutput(LAN_PORT)]
		self.add_flow(datapath=datapath, table_id=4, priority=97,
						match=match, actions=actions)


		# Line 4
		match = ofparser.OFPMatch(in_port=LAN_PORT, eth_type=0x0800, ipv4_src='10.0.0.2', ip_proto = 6, tcp_src=80)
		actions = [ofparser.OFPActionSetField(ipv4_src='1.0.0.1'),
				   ofparser.OFPActionSetField(tcp_src=80),
				   ofparser.OFPActionSetField(eth_dst="00:00:00:00:00:01"),
				   ofparser.OFPActionOutput(INTERNET_PORT)]
		self.add_flow(datapath=datapath, table_id=4, priority=96,
						match=match, actions=actions)

		# Line 5
		match = ofparser.OFPMatch(in_port=LAN_PORT, eth_type=0x0800, ipv4_src='10.0.0.3', ip_proto = 6, tcp_src=80)
		actions = [ofparser.OFPActionSetField(ipv4_src='1.0.0.1'),
				   ofparser.OFPActionSetField(tcp_src=80),
				   ofparser.OFPActionSetField(eth_dst="00:00:00:00:00:01"),
				   ofparser.OFPActionOutput(INTERNET_PORT)]
		self.add_flow(datapath=datapath, table_id=4, priority=95,
						match=match, actions=actions)

		# Line 6
		match = ofparser.OFPMatch()
		actions = [ofparser.OFPActionSetField(eth_dst="00:00:00:00:00:01"),
		ofparser.OFPActionOutput(INTERNET_PORT)]
		self.add_flow(datapath=datapath, table_id=4, priority=94,
						match=match, actions=actions)


	def install_forward(self, datapath):

		match = ofparser.OFPMatch()
		actions = [ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=10, match=match, instructions=inst)
		datapath.send_msg(mod)
