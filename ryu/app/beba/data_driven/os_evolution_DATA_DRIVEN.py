'''
Data driven network topology discovery
This use case is a new approach for L2 spanning tree. 
As in the standard mac learning procedures defined in 802.1d, each switch learns the binding between the MAC source address 
and the input port from which packets are received. Differently from the standard mechanism, the data packet piggybacks a metadata 
that represents the sum of the weights of all the links traversed by the packet. In this way, the switch learns the total weight for 
the paths to all destinations and are thus able to bind the best port to each source mac address by simply choosing the one associated 
to the path with the least total weight.
This use case considers two types of switches. The transport switches have only switch-to-switch links and consists of three OPP stages, 
respectively responsible for: (1) summing the input link weight to each incoming packet; (2) keeping the best reverse path for each flow 
(identified by the source mac address); (3) performing the final L2 forwarding.
The edge switches, executes all functions implemented by the transport switches (with few minimal differences) plus the detection of duplicated packets. 

Step-by-step Simulation Startup
1) Launch server load balancing controller application in Mininet by typing the following command:
$ ryu-manager ~/beba-ctrl/ryu/app/beba/os_evolution_DATA_DRIVEN.py

2) Start Mininet with a custom topology:
$ sudo python start_mn_mytopo_DATA_DRIVEN 

3) Write inside the terminals of Mininet the following commands :
$ h1 ping h2 -c 6 

4) To see the flow entries of switch s1 write : 
$ sh sudo dpctl -c unix:/tmp/s1 stats-flow

4) To see the state entries of switch s1 write : 
$ sh sudo dpctl -c unix:/tmp/s1 stats-state

The flow data value associated to the state represent the best known path to the host.

Custom Topology :


host1 ---- switch1 -- switch2 ----- switch4 -- switch6 ----host2 
                  \      |              |     / 
                   \     |              |    /  
                      switch3 ------- switch5 

'''


import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as osproto
import ryu.ofproto.beba_v1_0_parser as osparser


LOG = logging.getLogger('app.openstate.evolution')

# Number of switch ports
N = 3
#host port of edge switches
HOST_PORT = 1


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
		

		if datapath.id == 1 or datapath.id == 6:
			self.install_edge(datapath)
		else:
			if datapath.id == 2:
				self.install_transport_bad(datapath)
			else:
				self.install_transport(datapath)



############################################################ FUNCTION SWITCH EDGE #######################################################################################

	def install_edge(self, datapath):


		""" Table 0 is stateless """
		""" Set table 1 as stateful for GD"""	
		req = osparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=1,
				stateful=1)
		datapath.send_msg(req)

		""" Set table 3 as stateful """
		req = osparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=3,
				stateful=1)
		datapath.send_msg(req)


		""" Set table 4 as stateful """
		req = osparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=4,
				stateful=1)
		datapath.send_msg(req)

		""" Set table 5 as stateful """
		req = osparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=5,
				stateful=1)
		datapath.send_msg(req)


	############################### LOOKUP/UPDATE ################
		""" Tab1 """
		""" Don't care """ 
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=1)
		datapath.send_msg(req)
 
		""" Don't care """ 
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=1)
		datapath.send_msg(req)


		""" Tab3 """
		""" Set lookup extractor = {MPLS_label} """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_MPLS_LABEL],
				table_id=3)
		datapath.send_msg(req)

		""" Set update extractor = {MPLS_label}  """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_MPLS_LABEL],
				table_id=3)
		datapath.send_msg(req)


		""" Tab4 """
		""" Set lookup extractor = {MAC_SRC} """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=4)
		datapath.send_msg(req)

		""" Set update extractor = {MAC_SRC}  """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=4)
		datapath.send_msg(req)


		""" Tab5 """
		""" Set lookup extractor = {MAC_DST} """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_DST],
				table_id=5)
		datapath.send_msg(req)

		""" Set update extractor = {MAC_SRC}  """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=5)
		datapath.send_msg(req)


		########################### SET HF GD DATA VARIABLE TAB 1 ############################################


		''' GD[0] = datapath.id<<6 + sequence number'''
		req = osparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=1,
				global_data_variable_id=0,
				value=(datapath.id<<6) + 1)				
		datapath.send_msg(req)


		########################### SET HF GD DATA VARIABLE TAB 3 ############################################


		''' HF[0] = OXM_OF_MPLS_LABEL [id_pkt] '''
		req = osparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=3,
				extractor_id=0,
				field=ofproto.OXM_OF_MPLS_LABEL
			)
		datapath.send_msg(req)


		''' HF[1] = OXM_OF_MPLS_TC [linkWeight] '''
		req = osparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=3,
				extractor_id=1,
				field=ofproto.OXM_OF_MPLS_TC
			)
		datapath.send_msg(req)


		''' GD[0] = 0 '''
		req = osparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=3,
				global_data_variable_id=0,
				value=0)				
		datapath.send_msg(req)


		''' GD[1] = datapath.id '''
		req = osparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=3,
				global_data_variable_id=1,
				value=0)				
		datapath.send_msg(req)

		########################### SET HF GD DATA VARIABLE TAB 4 ############################################

		''' HF[0] = OXM_OF_MPLS_LABEL [id_pkt] '''
		req = osparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=4,
				extractor_id=0,
				field=ofproto.OXM_OF_MPLS_LABEL
			)
		datapath.send_msg(req)



		''' HF[1] = OXM_OF_MPLS_TC [linkWeight] '''
		req = osparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=4,
				extractor_id=1,
				field=ofproto.OXM_OF_MPLS_TC
			)
		datapath.send_msg(req)


		''' GD[0] = datapath.id '''
		req = osparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=4,
				global_data_variable_id=0,
				value=1)				
		datapath.send_msg(req)


		########################### SET CONDITION TAB 4 ############################################


		# condition 0: MPLS_TC <= KNOWN WEIGHT (FD[0])
		# condition 0: HF[1] <= FD[0] ?		
		req = osparser.OFPExpMsgSetCondition(
				datapath=datapath,
				table_id=4,
				condition_id=0,
				condition=osproto.CONDITION_LTE,
				operand_1_hf_id=1,
				operand_2_fd_id=0
			)
		datapath.send_msg(req)

		# condition 1: MPLS_TC <= 1   --> first hop
		# condition 1: HF[1] <= GD[0] ?		
		req = osparser.OFPExpMsgSetCondition(
				datapath=datapath,
				table_id=4,
				condition_id=1,
				condition=osproto.CONDITION_LTE,
				operand_1_hf_id=1,
				operand_2_gd_id=0
			)
		datapath.send_msg(req)


		''' #######################  TAB 0 PushLabelMPLS  '''
		# Input from host port (HOST_PORT) push label mpls e GOTO Tab 1
		match = ofparser.OFPMatch(in_port = HOST_PORT)
		actions = [ofparser.OFPActionPushMpls()]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(1)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=8, match=match, instructions=inst)
		datapath.send_msg(mod)

		
		match = ofparser.OFPMatch()
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(1)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=0, match=match, instructions=inst)
		datapath.send_msg(mod)


		''' #######################  TAB 1 mark pkt with ID_PKT  '''
		# Set label_mpls: GD[0] + 1 -> (id_switch << 6) + 1
		match = ofparser.OFPMatch(eth_type=0x8847, mpls_label=0)
		actions = [osparser.OFPExpActionWriteContextToField(src_type=osproto.SOURCE_TYPE_GLOBAL_DATA_VAR,src_id=0,dst_field=ofproto.OXM_OF_MPLS_LABEL),
					 osparser.OFPExpActionSetDataVariable(table_id=1, opcode=osproto.OPCODE_SUM, output_gd_id=0, operand_1_gd_id=0, operand_2_cost=1)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(2)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=1,
								priority=8, match=match, instructions=inst)
		datapath.send_msg(mod)


		match = ofparser.OFPMatch(eth_type=0x8847)
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
				ofparser.OFPInstructionGotoTable(2)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=1,
								priority=0, match=match, instructions=inst)
		datapath.send_msg(mod)


		''' #######################  TAB 2 '''
		match = ofparser.OFPMatch(eth_type=0x8847)
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(3)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=2,
								priority=0, match=match, instructions=inst)
		datapath.send_msg(mod)


		'''####################### TAB 3 Check duplicate, State: mpls_label'''
		""" Line 1 """

		# GD[0] = HF[1] + 1 -> MPLS_TC + 1
		# HF [1] = GD[0] -> MPLS_TC = GD[0]
		# WriteMetadata = 1 -> duplicate pkt
		# SetState(1)
		# GOTO Tab 2
		match = ofparser.OFPMatch(state=1, eth_type=0x8847)
		actions = [osparser.OFPExpActionSetDataVariable(table_id=3, opcode=osproto.OPCODE_SUM, output_gd_id=0, operand_1_hf_id=1, operand_2_cost=1),
					osparser.OFPExpActionWriteContextToField(src_type=osproto.SOURCE_TYPE_GLOBAL_DATA_VAR,src_id=0,dst_field=ofproto.OXM_OF_MPLS_TC),
					# osparser.OFPExpActionSetState(state=1, table_id=3, idle_timeout=15)]
					osparser.OFPExpActionSetState(state=1, table_id=3)]					
		inst = [ofparser.OFPInstructionActions(
				ofproto.OFPIT_APPLY_ACTIONS, actions),
				ofparser.OFPInstructionWriteMetadata( metadata = 1, metadata_mask = 0xFFFFFFFF ),
				ofparser.OFPInstructionGotoTable(4)]
		
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=3,
								priority=1198, match=match, instructions=inst)
		datapath.send_msg(mod)




		""" Line 2 """

		# GD[0] = HF[1] + 1 -> MPLS_TC + 1
		# HF [1] = GD[0] -> MPLS_TC = GD[0]
		# SetState(1)
		# GOTO Tab 4
		match = ofparser.OFPMatch(state=0, eth_type=0x8847)
		actions = [osparser.OFPExpActionSetDataVariable(table_id=3, opcode=osproto.OPCODE_SUM, output_gd_id=0, operand_1_hf_id=1, operand_2_cost=1),
					osparser.OFPExpActionWriteContextToField(src_type=osproto.SOURCE_TYPE_GLOBAL_DATA_VAR,src_id=0,dst_field=ofproto.OXM_OF_MPLS_TC),					
					osparser.OFPExpActionSetState(state=1, table_id=3)]
		inst = [ofparser.OFPInstructionActions(
				ofproto.OFPIT_APPLY_ACTIONS, actions),
				ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=3,
								priority=198, match=match, instructions=inst)
		datapath.send_msg(mod)



		'''# #######################  TAB 4 check condition C[0] e C[1]'''

		""" Line 1 """

		# C[0]: MPLS_TC > KNOWN WEIGHT -> HF[1] > FD[0]
		# MetaData: 1 -> duplicate pkt
		# action DROP
		match = ofparser.OFPMatch(state=1, eth_type=0x8847, condition0=0, metadata = 1)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=4)]
		self.add_flow(datapath=datapath,
				table_id=4,
				priority=1198,
				match=match,
				actions=actions)



		""" Line 2 """

		# C[0]: MPLS_TC > KNOWN WEIGHT -> HF[1] > FD[0]
		# MetaData: 0 -> NOT duplicate
		# SetState(1)
		# WriteMetadata = 3 -> WORSE PATH, NOT duplicate
		# action GOTO Tab 3
		match = ofparser.OFPMatch(state=1, eth_type=0x8847, condition0=0, condition1=0, metadata=0)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=4),
					ofparser.OFPActionPopMpls()]
		inst = [ofparser.OFPInstructionActions(
				ofproto.OFPIT_APPLY_ACTIONS, actions),
				ofparser.OFPInstructionWriteMetadata( metadata = 3, metadata_mask = 0xFFFFFFFF ),
				ofparser.OFPInstructionGotoTable(5)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=4,
								priority=198, match=match, instructions=inst)
		datapath.send_msg(mod)

		""" Line 2 BIS """

		# C[0]: MPLS_TC > KNOWN WEIGHT -> HF[1] > FD[0]
		# MetaData: 0 -> NOT duplicate
		# SetState(1)
		# WriteMetadata = 3 -> WORSE PATH, NOT duplicate
		# action GOTO Tab 3
		match = ofparser.OFPMatch(state=1, eth_type=0x8847, condition0=0, condition1=1, metadata=0)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=4)]
		inst = [ofparser.OFPInstructionActions(
				ofproto.OFPIT_APPLY_ACTIONS, actions),
				ofparser.OFPInstructionWriteMetadata( metadata = 3, metadata_mask = 0xFFFFFFFF ),
				ofparser.OFPInstructionGotoTable(5)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=4,
								priority=198, match=match, instructions=inst)
		datapath.send_msg(mod)

		""" Line 3 """

		# C[0]: MPLS_TC <= KNOWN WEIGHT -> HF[1] <= FD[0]
		# FD[0] = HF[1] -> KNOWN WEIGHT = MPLS_TC
		# SetState(1)
		# action GOTO Tab 3
		match = ofparser.OFPMatch(state=1, eth_type=0x8847, condition0=1, condition1=0)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=4),
					 osparser.OFPExpActionSetDataVariable(table_id=4, opcode=osproto.OPCODE_SUM, output_fd_id=0, operand_1_hf_id=1, operand_2_cost=0),
					ofparser.OFPActionPopMpls()]
		inst = [ofparser.OFPInstructionActions(
				 ofproto.OFPIT_APPLY_ACTIONS, actions),
				 ofparser.OFPInstructionGotoTable(5)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=4,
								priority=98, match=match, instructions=inst)
		datapath.send_msg(mod)

		""" Line 3 BIS """

		# C[0]: MPLS_TC <= KNOWN WEIGHT -> HF[1] <= FD[0]
		# FD[0] = HF[1] -> KNOWN WEIGHT = MPLS_TC
		# SetState(1)
		# action GOTO Tab 3
		match = ofparser.OFPMatch(state=1, eth_type=0x8847, condition0=1, condition1=1)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=4),
					osparser.OFPExpActionSetDataVariable(table_id=4, opcode=osproto.OPCODE_SUM, output_fd_id=0, operand_1_hf_id=1, operand_2_cost=0)]
		inst = [ofparser.OFPInstructionActions(
				 ofproto.OFPIT_APPLY_ACTIONS, actions),
				 ofparser.OFPInstructionGotoTable(5)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=4,
								priority=98, match=match, instructions=inst)
		datapath.send_msg(mod)


		""" Line 4 """

		# FD[0] = HF[1] -> KNOWN WEIGHT = MPLS_TC
		# SetState(1)
		# action GOTO Tab 3
		match = ofparser.OFPMatch(state=0, eth_type=0x8847, condition1=0)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=4),
					osparser.OFPExpActionSetDataVariable(table_id=4, opcode=osproto.OPCODE_SUM, output_fd_id=0, operand_1_hf_id=1, operand_2_cost=0),
					ofparser.OFPActionPopMpls()]
		inst = [ofparser.OFPInstructionActions(
				ofproto.OFPIT_APPLY_ACTIONS, actions),
				ofparser.OFPInstructionGotoTable(5)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=4,
								priority=8, match=match, instructions=inst)
		datapath.send_msg(mod)

		""" Line 4 BIS """

		# FD[0] = HF[1] -> KNOWN WEIGHT = MPLS_TC
		# SetState(1)
		# action GOTO Tab 3
		match = ofparser.OFPMatch(state=0, eth_type=0x8847, condition1=1)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=4),
					osparser.OFPExpActionSetDataVariable(table_id=4, opcode=osproto.OPCODE_SUM, output_fd_id=0, operand_1_hf_id=1, operand_2_cost=0)]
		inst = [ofparser.OFPInstructionActions(
				ofproto.OFPIT_APPLY_ACTIONS, actions),
				ofparser.OFPInstructionGotoTable(5)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=4,
								priority=8, match=match, instructions=inst)
		datapath.send_msg(mod)


		'''# #######################  TAB 5  simply MAC Learning '''
		''' Mac Learning, check if metadata = 1 or metadata = 3 '''
		
		# For each input port, for each state
		for i in range(1, N+1):
			for s in range(N+1):
				match = ofparser.OFPMatch(in_port=i, state=s)
				if s == 0:
					out_port = ofproto.OFPP_FLOOD
				else:
					out_port = s

				# actions = [osparser.OFPExpActionSetState(state=i, table_id=5, hard_timeout=10),
				actions = [osparser.OFPExpActionSetState(state=i, table_id=5),
							ofparser.OFPActionOutput(out_port)]
				self.add_flow(datapath=datapath, table_id=5, priority=0,
								match=match, actions=actions)

			# DROP duplicate pkt (metadata = 1)
			match = ofparser.OFPMatch(in_port=i, metadata = 1)
			# actions = [osparser.OFPExpActionSetState(state=i, table_id=5, hard_timeout=10)]
			actions = [osparser.OFPExpActionSetState(state=i, table_id=5)]
			self.add_flow(datapath=datapath, table_id=5, priority=1198,
							match=match, actions=actions)

		# For each state
		for s in range(N+1):
			match = ofparser.OFPMatch(state=s, metadata = 3)
			if s == 0:
				out_port = ofproto.OFPP_FLOOD
			else:
				out_port = s

			actions = [ofparser.OFPActionOutput(out_port)]
			self.add_flow(datapath=datapath, table_id=5, priority=198,
							match=match, actions=actions)




############################################################ FUNCTION SWITCH TRANSPORT #######################################################################################




	def install_transport(self, datapath):



		""" Set table 0 as stateful for GD """	
		req = osparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=0,
				stateful=1)
		datapath.send_msg(req)

		""" Set table 2 as stateful, check condition """
		req = osparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=2,
				stateful=1)
		datapath.send_msg(req)


		""" Set table 3 as stateful """
		req = osparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=3,
				stateful=1)
		datapath.send_msg(req)



	############################### LOOKUP/UPDATE ################
		""" Tab0 """
		""" Don't care """ 
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=0)
		datapath.send_msg(req)

		""" Don't care """ 
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=0)
		datapath.send_msg(req)


		""" Tab2 """
		""" Set lookup extractor = {MAC_SRC} """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=2)
		datapath.send_msg(req)

		""" Set update extractor = {MAC_SRC}  """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=2)
		datapath.send_msg(req)


		""" Tab3 """
		""" Set lookup extractor = {MAC_DST} """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_DST],
				table_id=3)
		datapath.send_msg(req)

		""" Set update extractor = {MAC_SRC}  """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=3)
		datapath.send_msg(req)



		########################### SET HF GD DATA VARIABLE TAB 0 ############################################


		''' HF[1] = OXM_OF_MPLS_TC [linkWeight] '''
		req = osparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=0,
				extractor_id=1,
				field=ofproto.OXM_OF_MPLS_TC
			)
		datapath.send_msg(req)


		''' GD[0] = 0 '''
		req = osparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=0,
				value=0)				
		datapath.send_msg(req)


		########################### SET HF GD DATA VARIABLE TAB 2 ############################################



		''' HF[1] = OXM_OF_MPLS_TC [linkWeight] '''
		req = osparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=2,
				extractor_id=1,
				field=ofproto.OXM_OF_MPLS_TC
			)
		datapath.send_msg(req)


		########################### SET CONDITION TAB 2 ############################################


		# condition 3: MPLS_TC <= KNOWN WEIGHT (FD[0]) ?
		# condition 3: HF[1] <= FD[0] ?		
		req = osparser.OFPExpMsgSetCondition(
				datapath=datapath,
				table_id=2,
				condition_id=0,
				condition=osproto.CONDITION_LTE,
				operand_1_hf_id=1,
				operand_2_fd_id=0
			)
		datapath.send_msg(req)




		'''####################### TAB 0 '''
		""" Line 1 """

		# GD[0] = HF[1] + 1 -> MPLS_TC + 1
		# HF [1] = GD[0] -> MPLS_TC = GD[0]
		# GOTO Tab 2
		match = ofparser.OFPMatch(eth_type=0x8847)
		actions = [osparser.OFPExpActionSetDataVariable(table_id=0, opcode=osproto.OPCODE_SUM, output_gd_id=0, operand_1_hf_id=1, operand_2_cost=1),
					osparser.OFPExpActionWriteContextToField(src_type=osproto.SOURCE_TYPE_GLOBAL_DATA_VAR,src_id=0,dst_field=ofproto.OXM_OF_MPLS_TC)]
		inst = [ofparser.OFPInstructionActions(
				ofproto.OFPIT_APPLY_ACTIONS, actions),
				ofparser.OFPInstructionGotoTable(1)]		
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=1198, match=match, instructions=inst)
		datapath.send_msg(mod)



		''' #######################  TAB 1 '''
		match = ofparser.OFPMatch(eth_type=0x8847)
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(2)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=1,
								priority=0, match=match, instructions=inst)
		datapath.send_msg(mod)





		'''# #######################  TAB 2 '''

		# C[0]: MPLS_TC > KNOWN WEIGHT -> HF[1] > FD[0]
		# MetaData: 1 -> Duplicate pkt
		# action DROP
		match = ofparser.OFPMatch(state=1, eth_type=0x8847, condition0=0)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=2)]
		self.add_flow(datapath=datapath,
				table_id=2,
				priority=198,
				match=match,
				actions=actions)

		
		""" Line 2 """

		# C[0]: MPLS_TC <= KNOWN WEIGHT -> HF[1] <= FD[0]
		# FD[0] = HF[1] -> KNOWN WEIGHT = MPLS_TC
		# SetState(1)
		# action GOTO Tab 3
		match = ofparser.OFPMatch(state=1, eth_type=0x8847, condition0=1)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=2),
					osparser.OFPExpActionSetDataVariable(table_id=2, opcode=osproto.OPCODE_SUM, output_fd_id=0, operand_1_hf_id=1, operand_2_cost=0)]
		inst = [ofparser.OFPInstructionActions(
				 ofproto.OFPIT_APPLY_ACTIONS, actions),
				 ofparser.OFPInstructionGotoTable(3)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=2,
								priority=98, match=match, instructions=inst)
		datapath.send_msg(mod)


		""" Line 3 """

		# FD[0] = HF[1] -> KNOWN WEIGHT = MPLS_TC
		# SetState(1)
		# action GOTO Tab 3
		match = ofparser.OFPMatch(state=0, eth_type=0x8847)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=2),
					osparser.OFPExpActionSetDataVariable(table_id=2, opcode=osproto.OPCODE_SUM, output_fd_id=0, operand_1_hf_id=1, operand_2_cost=0)]
		inst = [ofparser.OFPInstructionActions(
				ofproto.OFPIT_APPLY_ACTIONS, actions),
				ofparser.OFPInstructionGotoTable(3)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=2,
								priority=8, match=match, instructions=inst)
		datapath.send_msg(mod)


		'''# #######################  TAB 3  simply MAC Learning '''

		# for each input port, for each state
		for i in range(1, N+1):
			for s in range(N+1):
				match = ofparser.OFPMatch(in_port=i, state=s)
				if s == 0:
					out_port = ofproto.OFPP_FLOOD
				else:
					out_port = s
				# actions = [osparser.OFPExpActionSetState(state=i, table_id=3, hard_timeout=10),
				actions = [osparser.OFPExpActionSetState(state=i, table_id=3),
							ofparser.OFPActionOutput(out_port)]
				self.add_flow(datapath=datapath, table_id=3, priority=0,
								match=match, actions=actions)




	def install_transport_bad(self, datapath):


		""" Set table 0 as stateful for GD """
		req = osparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=0,
				stateful=1)
		datapath.send_msg(req)


		""" Set table 2 as stateful, check condition path"""
		req = osparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=2,
				stateful=1)
		datapath.send_msg(req)


		""" Set table 3 as stateful """
		req = osparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=3,
				stateful=1)
		datapath.send_msg(req)



	############################### LOOKUP/UPDATE ################
		""" Tab0 """
		""" Don't care """ 
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=0)
		datapath.send_msg(req)

		""" Don't care """ 
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=0)
		datapath.send_msg(req)


		""" Tab2 """
		""" Set lookup extractor = {MAC_SRC} """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=2)
		datapath.send_msg(req)

		""" Set update extractor = {MAC_SRC}  """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=2)
		datapath.send_msg(req)


		""" Tab3 """
		""" Set lookup extractor = {MAC_DST} """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_DST],
				table_id=3)
		datapath.send_msg(req)

		""" Set update extractor = {MAC_SRC}  """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=3)
		datapath.send_msg(req)



		########################### SET HF GD DATA VARIABLE TAB 0 ############################################


		''' HF[1] = OXM_OF_MPLS_TC [linkWeight] '''
		req = osparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=0,
				extractor_id=1,
				field=ofproto.OXM_OF_MPLS_TC
			)
		datapath.send_msg(req)


		''' GD[0] = 0 '''
		req = osparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=0,
				value=0)				
		datapath.send_msg(req)


		########################### SET HF GD DATA VARIABLE TAB 2 ############################################



		''' HF[1] = OXM_OF_MPLS_TC [linkWeight] '''
		req = osparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=2,
				extractor_id=1,
				field=ofproto.OXM_OF_MPLS_TC
			)
		datapath.send_msg(req)


		########################### SET CONDITION TAB 2 ############################################


		# condition 3: MPLS_TC <= KNOWN WEIGHT (FD[0]) ?
		# condition 3: HF[1] <= FD[0] ?		
		req = osparser.OFPExpMsgSetCondition(
				datapath=datapath,
				table_id=2,
				condition_id=0,
				condition=osproto.CONDITION_LTE,
				operand_1_hf_id=1,
				operand_2_fd_id=0
			)
		datapath.send_msg(req)




		'''####################### TAB 0 '''
		""" Line 1 """

		# GD[0] = HF[1] + 1 -> MPLS_TC + 1
		# HF [1] = GD[0] -> MPLS_TC = GD[0]
		# GOTO Tab 2
		match = ofparser.OFPMatch(eth_type=0x8847)
		actions = [osparser.OFPExpActionSetDataVariable(table_id=0, opcode=osproto.OPCODE_SUM, output_gd_id=0, operand_1_hf_id=1, operand_2_cost=2),
					osparser.OFPExpActionWriteContextToField(src_type=osproto.SOURCE_TYPE_GLOBAL_DATA_VAR,src_id=0,dst_field=ofproto.OXM_OF_MPLS_TC)]
		inst = [ofparser.OFPInstructionActions(
				ofproto.OFPIT_APPLY_ACTIONS, actions),
				ofparser.OFPInstructionGotoTable(1)]		
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=1198, match=match, instructions=inst)
		datapath.send_msg(mod)



		''' #######################  TAB 1 '''

		match = ofparser.OFPMatch(eth_type=0x8847)
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(2)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=1,
								priority=0, match=match, instructions=inst)
		datapath.send_msg(mod)





		'''# #######################  TAB 2 '''
		""" Line 1 """

		# C[0]: MPLS_TC > KNOWN WEIGHT -> HF[1] > FD[0]
		# MetaData: 1 -> Duplicate pkt
		# action DROP
		match = ofparser.OFPMatch(state=1, eth_type=0x8847, condition0=0)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=2)]
		self.add_flow(datapath=datapath,
				table_id=2,
				priority=198,
				match=match,
				actions=actions)


		""" Line 2 """

		# C[0]: MPLS_TC <= KNOWN WEIGHT -> HF[1] <= FD[0]
		# FD[0] = HF[1] -> KNOWN WEIGHT = MPLS_TC
		# SetState(1)
		# action GOTO Tab 3
		match = ofparser.OFPMatch(state=1, eth_type=0x8847, condition0=1)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=2),
					osparser.OFPExpActionSetDataVariable(table_id=2, opcode=osproto.OPCODE_SUM, output_fd_id=0, operand_1_hf_id=1, operand_2_cost=0)]
		inst = [ofparser.OFPInstructionActions(
				 ofproto.OFPIT_APPLY_ACTIONS, actions),
				 ofparser.OFPInstructionGotoTable(3)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=2,
								priority=98, match=match, instructions=inst)
		datapath.send_msg(mod)


		""" Line 3 """

		# FD[0] = HF[1] -> KNOWN WEIGHT = MPLS_TC
		# SetState(1)
		# action GOTO Tab 3
		match = ofparser.OFPMatch(state=0, eth_type=0x8847)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=2),
					osparser.OFPExpActionSetDataVariable(table_id=2, opcode=osproto.OPCODE_SUM, output_fd_id=0, operand_1_hf_id=1, operand_2_cost=0)]
		inst = [ofparser.OFPInstructionActions(
				ofproto.OFPIT_APPLY_ACTIONS, actions),
				ofparser.OFPInstructionGotoTable(3)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=2,
								priority=8, match=match, instructions=inst)
		datapath.send_msg(mod)


		'''# #######################  TAB 3  simply MAC Learning '''

		# for each input port, for each state
		for i in range(1, N+1):
			for s in range(N+1):
				match = ofparser.OFPMatch(in_port=i, state=s)
				if s == 0:
					out_port = ofproto.OFPP_FLOOD
				else:
					out_port = s
				# actions = [osparser.OFPExpActionSetState(state=i, table_id=3, hard_timeout=10),
				actions = [osparser.OFPExpActionSetState(state=i, table_id=3),
							ofparser.OFPActionOutput(out_port)]
				self.add_flow(datapath=datapath, table_id=3, priority=0,
								match=match, actions=actions)


