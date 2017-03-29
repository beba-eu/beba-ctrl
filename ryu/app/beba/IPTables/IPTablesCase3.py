'''
3. Dynamic NAT
Dynamic NAT between the LAN and the Internet, translating local source addresses into a public IP address, with a dynamically selected source port, and viceversa.

Step-by-step Simulation Startup
1) Launch server load balancing controller application in Mininet by typing the following command:
$ ryu-manager ~/beba-ctrl/ryu/app/beba/IPTablesCase3.py

2) Start Mininet with a custom topology:
$ sudo python start_mn_mytopo_IPTABLES

3) Write inside the terminals of Mininet the following commands :
$ xterm h1 h3

4) Write inside the terminals of h1 the following commands :
h1# nc -lvp 3000

5) Write inside the terminals of h3 the following commands :
h3# nc -v 1.0.0.2 3000

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
			self.function_dynamic_nat(datapath)




	'''########################################################################################################################################################## 
	############################################################################################################################################################# 
	##########################################################                            ####################################################################### 
	##########################################################    FUNCTION DYNAMIC NAT    #######################################################################  
	##########################################################                            #######################################################################
	##########################################################################################################################################################'''


	def function_dynamic_nat(self, datapath):

		""" Set table 0 as stateful """	
		req = bebaparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=0,
				stateful=1)
		datapath.send_msg(req)

		""" Set table 1 as stateful, tabella degli stati usata per le porte libere"""	
		req = bebaparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=1,
				stateful=1)
		datapath.send_msg(req)

		""" Set table 2 restore """	
		req = bebaparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=2,
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


		""" Tab1 """
		""" Set lookup extractor = {OXM_OF_METADATA} """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_METADATA],
				table_id=1)
		datapath.send_msg(req)

		""" Set update extractor = {OXM_OF_METADATA}  """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_METADATA],
				table_id=1)
		datapath.send_msg(req)


		""" Tab2 """
		""" Set lookup extractor = {OXM_OF_IPV4_SRC, OXM_OF_IP_PROTO, OXM_OF_TCP_SRC} """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_IPV4_SRC, ofproto.OXM_OF_IP_PROTO,
						ofproto.OXM_OF_TCP_SRC],
				table_id=2)
		datapath.send_msg(req)

		""" Set lookup extractor = {OXM_OF_IPV4_DST, OXM_OF_IP_PROTO, OXM_OF_TCP_DST} """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_IPV4_DST, ofproto.OXM_OF_IP_PROTO,
						ofproto.OXM_OF_TCP_DST],
				table_id=2)
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


		########################### SET STATE TABLE 1 ############################################


		for stateVal in range(1,21):
			state = bebaparser.OFPExpMsgSetFlowState(datapath=datapath,
					state=2000+stateVal,
					keys=[stateVal,0,0,0,0,0,0,0],
					table_id=1)
			datapath.send_msg(state)



		########################### SET HF DATA VARIABLE TAB 1 ############################################

		
		''' GD[0] = state_label''' 
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=1,
				global_data_variable_id=0,
				value=0)				
		datapath.send_msg(req)


		''' HF[0] = OXM_EXP_STATE [state_label] '''
		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=1,
				extractor_id=0,
				field=bebaproto.OXM_EXP_STATE
			)
		datapath.send_msg(req)
		
		########################### SET HF DATA VARIABLE TAB 2 ############################################

		''' HF[0] = OXM_OF_IPV4_SRC [id_pkt] '''
		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=2,
				extractor_id=0,
				field=ofproto.OXM_OF_IPV4_SRC
			)
		datapath.send_msg(req)

		''' HF[1] = OXM_OF_TCP_SRC [id_pkt] '''
		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=2,
				extractor_id=1,
				field=ofproto.OXM_OF_TCP_SRC
			)
		datapath.send_msg(req)

		########################### SET HF DATA VARIABLE TAB 3 ############################################

		''' HF[0] = OXM_OF_METADATA [metadata] '''
		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=3,
				extractor_id=0,
				field=ofproto.OXM_OF_METADATA
			)
		datapath.send_msg(req)


		''' GD[0] = 0''' 
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=3,
				global_data_variable_id=0,
				value=0)				
		datapath.send_msg(req)

		''' GD[1] = LAN_DUE 10.0.0.2 ''' 
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=3,
				global_data_variable_id=1,
				value=0x0200000a)				
		datapath.send_msg(req)

		''' GD[2] = LAN_TRE 10.0.0.3 ''' 
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=3,
				global_data_variable_id=2,
				value=0x0300000a)				
		datapath.send_msg(req)


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


		# Line 1
		match = ofparser.OFPMatch(state=0, in_port=LAN_PORT, eth_type=0x0800, ipv4_dst=('8.0.0.0','255.255.255.0'))
		actions = [bebaparser.OFPExpActionSetState(state=12, table_id=0)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionWriteMetadata(metadata=0, metadata_mask=0xFFFFFFFF),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=99, match=match, instructions=inst)
		datapath.send_msg(mod)


		match = ofparser.OFPMatch(state=0, in_port=LAN_PORT)
		actions = [bebaparser.OFPExpActionSetState(state=1, table_id=0),
				   bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_gd_id=1, operand_1_gd_id=1, operand_2_cost=1),
				   bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_GLOBAL_DATA_VAR,src_id=1,dst_field=ofproto.OXM_OF_METADATA)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(1)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=89, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 12
		match = ofparser.OFPMatch(state=1, in_port=LAN_PORT)
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(3)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=88, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 13
		match = ofparser.OFPMatch(state=0, in_port=INTERNET_PORT, eth_type=0x0800, ipv4_dst='1.0.0.1')
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(2)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=87, match=match, instructions=inst)
		datapath.send_msg(mod)


		''' #######################  TAB 1  ''' 

		# Line 0
		# HF[0] = state_label
		# GD[0] = state_label + 0 => GD[0] + HF[0]
		# state_label -> metadata => GD[0] = HF[0]
		match = ofparser.OFPMatch(in_port=3, eth_type=0x0800)
		actions = [bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_gd_id=0, operand_1_hf_id=0, operand_2_cost=0),
					bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_GLOBAL_DATA_VAR,src_id=0,dst_field=ofproto.OXM_OF_METADATA)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			# ofparser.OFPInstructionWriteMetadata(metadata=state_label, metadata_mask=0xFFFFFFFF),
			ofparser.OFPInstructionGotoTable(2)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=1,
								priority=100, match=match, instructions=inst)
		datapath.send_msg(mod)


		''' #######################  TAB 2 restore'''

		# Line 0
		# ip.src -> R0 => HF[0] -> FD[0] => FD[0] = HF[0] + 0
		# tcp.src -> R1 => HF[1] -> FD[1] => FD[1] = HF[1] + 0
		match = ofparser.OFPMatch(state=0, in_port=LAN_PORT, eth_type=0x0800)
		actions = [bebaparser.OFPExpActionSetState(state=1, table_id=2),
				   bebaparser.OFPExpActionSetDataVariable(table_id=2, opcode=bebaproto.OPCODE_SUM, output_fd_id=0, operand_1_hf_id=0, operand_2_cost=0),
				   bebaparser.OFPExpActionSetDataVariable(table_id=2, opcode=bebaproto.OPCODE_SUM, output_fd_id=1, operand_1_hf_id=1, operand_2_cost=0)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(3)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=2,
								priority=100, match=match, instructions=inst)
		datapath.send_msg(mod)


		# Line 1
		# ip.dst = R0 => IPV4_DST = FD[0] 
		# tcp.dst = R1 => TCP_DST = FD[1]
		match = ofparser.OFPMatch(state=1, in_port=INTERNET_PORT, eth_type=0x0800)
		actions = [bebaparser.OFPExpActionSetState(state=1, table_id=2),
				   bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_FLOW_DATA_VAR,src_id=0,dst_field=ofproto.OXM_OF_IPV4_DST),
				   bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_FLOW_DATA_VAR,src_id=1,dst_field=ofproto.OXM_OF_TCP_DST)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=2,
								priority=99, match=match, instructions=inst)
		datapath.send_msg(mod)


		''' #######################  TAB 3 translate ''' 

		# Line 3
		# metadata(b16,b31) -> R1 => metadata(b16,b31) -> FD[1] => FD[1] = HF[0]
		# ip.src = 10.0.0.1
		# tcp.src = R1 => TCP_SRC = FD[1]
		match = ofparser.OFPMatch(state=0, in_port=LAN_PORT, eth_type=0x0800)
		actions = [bebaparser.OFPExpActionSetState(state=1, table_id=3),
				   bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM, output_fd_id=1, operand_1_hf_id=0, operand_2_cost=0),
				   ofparser.OFPActionSetField(ipv4_src="1.0.0.1"),
				   bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_FLOW_DATA_VAR,src_id=1,dst_field=ofproto.OXM_OF_TCP_SRC)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=3,
								priority=97, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 4
		# ip.src = 10.0.0.1
		# tcp.src = R1 => TCP_SRC = FD[1]
		match = ofparser.OFPMatch(state=1, in_port=LAN_PORT, eth_type=0x0800)
		actions = [bebaparser.OFPExpActionSetState(state=1, table_id=3),
				   ofparser.OFPActionSetField(ipv4_src='1.0.0.1'),
				   bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_FLOW_DATA_VAR,src_id=1,dst_field=ofproto.OXM_OF_TCP_SRC)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=3,
								priority=96, match=match, instructions=inst)
		datapath.send_msg(mod)

		''' #######################  TAB 4 forward '''
		
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
