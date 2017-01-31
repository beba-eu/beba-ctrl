import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.openstate_v1_0 as osproto
import ryu.ofproto.openstate_v1_0_parser as osparser

LOG = logging.getLogger('app.openstate.evolution')


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
		
		self.install_function(datapath)


############################################################ FUNZIONE SWITCH EDGE #######################################################################################

	def install_function(self, datapath):

		""" Set table 0 as stateful """	
		req = osparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=0,
				stateful=1)
		datapath.send_msg(req)

		""" Set table 1 as stateful, tabella degli stati usata per le porte libere"""	
		req = osparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=1,
				stateful=1)
		datapath.send_msg(req)

		""" Set table 2 restore """	
		req = osparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=2,
				stateful=1)
		datapath.send_msg(req)

		""" Set table 3 translate """
		req = osparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=3,
				stateful=1)
		datapath.send_msg(req)


	############################### LOOKUP/UPDATE ###################################
		""" Tab0 """
		""" Set lookup extractor = {BiFlow} """ 
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_IPV4_SRC, ofproto.OXM_OF_IPV4_DST,
						ofproto.OXM_OF_IP_PROTO, ofproto.OXM_OF_TCP_SRC,
						ofproto.OXM_OF_TCP_DST],
				table_id=0,
				flag_L = 1)
		datapath.send_msg(req)
 
		""" Set lookup extractor = {BiFlow} """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_IPV4_SRC, ofproto.OXM_OF_IPV4_DST,
						ofproto.OXM_OF_IP_PROTO, ofproto.OXM_OF_TCP_SRC,
						ofproto.OXM_OF_TCP_DST],
				table_id=0,
				flag_L = 1)
		datapath.send_msg(req)

		""" Tab1 """
		""" Set lookup extractor = {OXM_OF_METADATA} """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_METADATA],
				table_id=1)
		datapath.send_msg(req)

		""" Set update extractor = {OXM_OF_METADATA}  """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_METADATA],
				table_id=1)
		datapath.send_msg(req)


		""" Tab2 """
		""" Set lookup extractor = {OXM_OF_IPV4_SRC, OXM_OF_IP_PROTO, OXM_OF_TCP_SRC} """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_IPV4_SRC, ofproto.OXM_OF_IP_PROTO,
						ofproto.OXM_OF_TCP_SRC],
				table_id=2)
		datapath.send_msg(req)

		""" Set lookup extractor = {OXM_OF_IPV4_DST, OXM_OF_IP_PROTO, OXM_OF_TCP_DST} """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_IPV4_DST, ofproto.OXM_OF_IP_PROTO,
						ofproto.OXM_OF_TCP_DST],
				table_id=2)
		datapath.send_msg(req)


		""" Tab3 """
		""" Set lookup extractor = {OXM_OF_IPV4_SRC, OXM_OF_TCP_SRC} """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_IPV4_SRC, ofproto.OXM_OF_TCP_SRC],
				table_id=3)
		datapath.send_msg(req)

		""" Set update extractor = {OXM_OF_IPV4_SRC, OXM_OF_TCP_SRC} """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_IPV4_SRC, ofproto.OXM_OF_TCP_SRC],
				table_id=3)
		datapath.send_msg(req)

		""" Tab4 """
		""" Stateless """

		########################### SET GD DATA VARIABLE TAB 0 ############################################


		''' GD[0] = 0''' 
		req = osparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=0,
				value=0)				
		datapath.send_msg(req)

		''' GD[1] = 0 '''
		req = osparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=0,
				value=0)				
		datapath.send_msg(req)

		
		########################### SET HF DATA VARIABLE TAB 2 ############################################

		''' HF[0] = OXM_OF_IPV4_SRC [id_pkt] '''
		req = osparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=2,
				extractor_id=0,
				field=ofproto.OXM_OF_IPV4_SRC
			)
		datapath.send_msg(req)

		''' HF[1] = OXM_OF_TCP_SRC [id_pkt] '''
		req = osparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=2,
				extractor_id=1,
				field=ofproto.OXM_OF_TCP_SRC
			)
		datapath.send_msg(req)


		########################### SET GD DATA VARIABLE TAB 3 ############################################


		''' GD[0] = 0''' 
		req = osparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=3,
				global_data_variable_id=0,
				value=0)				
		datapath.send_msg(req)


		########################### SET HF DATA VARIABLE TAB 4 ############################################
		# SI PUO FARE???

		''' HF[0] = OXM_OF_METADATA [id_pkt] '''
		req = osparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=4,
				extractor_id=0,
				field=ofproto.OXM_OF_METADATA
			)
		datapath.send_msg(req)


		################################# REGOLE ############################################


		''' #######################  TAB 0  '''  # tutto ok, controllare riga 7 e 11
		# Line 0
		match = ofparser.OFPMatch(state=0, in_port=1, ipv4_dst=10.0.0.0/24)
		actions = [osparser.OFPExpActionSetState(state=11, table_id=0)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionWriteMetadata(metadata=0, metadata_mask=0xFFFFFFFF),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=100, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 1
		match = ofparser.OFPMatch(state=0, in_port=2, ipv4_dst=8.0.0.0/24)
		actions = [osparser.OFPExpActionSetState(state=12, table_id=0)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionWriteMetadata(metadata=0, metadata_mask=0xFFFFFFFF),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=99, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 2
		match = ofparser.OFPMatch(state=11, in_port=1, ipv4_dst=10.0.0.0/24)
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionWriteMetadata(metadata=0, metadata_mask=0xFFFFFFFF),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=98, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 3
		match = ofparser.OFPMatch(state=11, in_port=2, ipv4_dst=8.0.0.0/24)
		actions = [osparser.OFPExpActionSetState(state=2, table_id=0)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionWriteMetadata(metadata=1, metadata_mask=0xFFFFFFFF),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=97, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 4
		match = ofparser.OFPMatch(state=12, in_port=2, ipv4_dst=8.0.0.0/24)
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionWriteMetadata(metadata=0, metadata_mask=0xFFFFFFFF),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=96, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 5
		match = ofparser.OFPMatch(state=12, in_port=1, ipv4_dst=10.0.0.0/24)
		actions = [osparser.OFPExpActionSetState(state=2, table_id=0)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionWriteMetadata(metadata=1, metadata_mask=0xFFFFFFFF),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=95, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 6
		match = ofparser.OFPMatch(state=2)
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionWriteMetadata(metadata=1, metadata_mask=0xFFFFFFFF),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=94, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 7
		match = ofparser.OFPMatch(state=0, in_port=0, ipv4_dst=10.0.0.1, tcp_dst=80)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=0),
				   osparser.OFPExpActionSetDataVariable(table_id=0, opcode=osproto.OPCODE_SUM, output_gd_id=0, operand_1_gd_id=0, operand_2_cost=1)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionWriteMetadata(metadata=G0, metadata_mask=0xFFFFFFFF),
			ofparser.OFPInstructionGotoTable(3)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=93, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 8
		match = ofparser.OFPMatch(state=1, in_port=0, ipv4_dst=10.0.0.1, tcp_dst=80)
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(3)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=92, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 9
		match = ofparser.OFPMatch(state=0, in_port=2, ipv4_src=10.0.0.2, tcp_src=80)
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=91, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 10
		match = ofparser.OFPMatch(state=0, in_port=2, ipv4_src=10.0.0.3, tcp_src=80)
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=90, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 11 VEDERE PROBLEMA DEL SET METADATA 16-31
		match = ofparser.OFPMatch(state=0, in_port=2)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=0),
				   osparser.OFPExpActionSetDataVariable(table_id=0, opcode=osproto.OPCODE_SUM, output_gd_id=1, operand_1_gd_id=1, operand_2_cost=1)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionWriteMetadata(metadata=G1, metadata_mask=0x0FFFF0000),
			ofparser.OFPInstructionGotoTable(1)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=89, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 12
		match = ofparser.OFPMatch(state=1, in_port=2)
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(3)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=88, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 13
		match = ofparser.OFPMatch(state=0, in_port=0, ipv4_dst=10.0.0.1)
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(2)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=87, match=match, instructions=inst)
		datapath.send_msg(mod)


		''' #######################  TAB 1 estrae la porta  ''' #controllare riga 0

		# Line 0 
		match = ofparser.OFPMatch(in_port=2)
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionWriteMetadata(metadata=state_label, metadata_mask=0xFFFFFFFF),
			ofparser.OFPInstructionGotoTable(2)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=1,
								priority=100, match=match, instructions=inst)
		datapath.send_msg(mod)


		''' #######################  TAB 2 restore'''

		# Line 0
		# ip.src -> R0 => HF[0] -> FD[0] => FD[0] = HF[0] + 0
		# tcp.src -> R1 => HF[1] -> FD[1] => FD[1] = HF[1] + 0
		match = ofparser.OFPMatch(state=0, in_port=2)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=2),
				   osparser.OFPExpActionSetDataVariable(table_id=2, opcode=osproto.OPCODE_SUM, output_fd_id=0, operand_1_hd_id=0, operand_2_cost=0),
				   osparser.OFPExpActionSetDataVariable(table_id=2, opcode=osproto.OPCODE_SUM, output_fd_id=1, operand_1_hd_id=1, operand_2_cost=0)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(3)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=2,
								priority=100, match=match, instructions=inst)
		datapath.send_msg(mod)


		# Line 1
		# ip.dst = R0 => IPV4_DST = FD[0] 
		# tcp.dst = R1 => TCP_DST = FD[1]
		match = ofparser.OFPMatch(state=1, in_port=0)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=2),
				   osparser.OFPExpActionWriteContextToField(src_type=osproto.SOURCE_TYPE_FLOW_DATA_VAR,src_id=0,dst_field=ofproto.OXM_OF_IPV4_DST),
				   osparser.OFPExpActionWriteContextToField(src_type=osproto.SOURCE_TYPE_FLOW_DATA_VAR,src_id=1,dst_field=ofproto.OXM_OF_TCP_DST)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=2,
								priority=99, match=match, instructions=inst)
		datapath.send_msg(mod)


		''' #######################  TAB 3 translate ''' # Controllare Riga 3

		# Line 0
		# ip.dst = 10.0.0.2 
		# tcp.dst = 80
		# 10.0.0.2 -> R0 => 10.0.0.2 -> FD[0] => FD[0] = GD[0] + 10.0.0.2 => 0 + 10.0.0.2
		# 80 -> R1 		 => 80 -> FD[1] 	  => GD[0] + 80 			  => 0 + 80
		match = ofparser.OFPMatch(state=0, in_port=0, metadata=0, metadata_mask=0x00000000F)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=3),
				   ofparser.OFPActionSetField(ipv4_dst=10.0.0.2),
				   ofparser.OFPActionSetField(tcp_dst=80),
				   osparser.OFPExpActionSetDataVariable(table_id=3, opcode=osproto.OPCODE_SUM, output_fd_id=0, operand_1_gd_id=0, operand_2_cost=10.0.0.2),
				   osparser.OFPExpActionSetDataVariable(table_id=3, opcode=osproto.OPCODE_SUM, output_fd_id=1, operand_1_gd_id=0, operand_2_cost=80)]
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
		match = ofparser.OFPMatch(state=0, in_port=0, metadata=1, metadata_mask=0x00000000F)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=3),
				   ofparser.OFPActionSetField(ipv4_dst=10.0.0.3),
				   ofparser.OFPActionSetField(tcp_dst=80),
				   osparser.OFPExpActionSetDataVariable(table_id=3, opcode=osproto.OPCODE_SUM, output_fd_id=0, operand_1_gd_id=0, operand_2_cost=10.0.0.2),
				   osparser.OFPExpActionSetDataVariable(table_id=3, opcode=osproto.OPCODE_SUM, output_fd_id=1, operand_1_gd_id=0, operand_2_cost=80)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=3,
								priority=99, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 2 
		# ip.dst = R0 => IPV4_DST = FD[0]
		# tcp.dst = R1 => TCP_DST = FD[1]
		match = ofparser.OFPMatch(state=1, in_port=0)
		actions = [osparser.OFPExpActionWriteContextToField(src_type=osproto.SOURCE_TYPE_FLOW_DATA_VAR,src_id=0,dst_field=ofproto.OXM_OF_IPV4_DST),
				   osparser.OFPExpActionWriteContextToField(src_type=osproto.SOURCE_TYPE_FLOW_DATA_VAR,src_id=1,dst_field=ofproto.OXM_OF_TCP_DST)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=3,
								priority=98, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 3 	DEVO SCRIVERE METADATA su una variabile in quealche modo
		# metadata(b16,b31) -> R1 => metadata(b16,b31) -> FD[1] => FD[1] = metadata(b16,b31)
		# ip.src = 10.0.0.1
		# tcp.src = R1 => TCP_SRC = FD[1]
		match = ofparser.OFPMatch(state=0, in_port=2)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=3),
				   
				   #Inserire riga per scrivere metadata in FD[1]
				   # osparser.OFPExpActionSetDataVariable(table_id=4, opcode=osproto.OPCODE_SUM, output_fd_id=1, operand_1_hf_id=0, operand_2_cost=0)]

				   ofparser.OFPActionSetField(ipv4_src=10.0.0.1),
				   osparser.OFPExpActionWriteContextToField(src_type=osproto.SOURCE_TYPE_FLOW_DATA_VAR,src_id=1,dst_field=ofproto.OXM_OF_TCP_SRC)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=3,
								priority=97, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 4
		# ip.src = 10.0.0.1
		# tcp.src = R1 => TCP_SRC = FD[1]
		match = ofparser.OFPMatch(state=1, in_port=2)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=3),
				   ofparser.OFPActionSetField(ipv4_src=10.0.0.1),
				   osparser.OFPExpActionWriteContextToField(src_type=osproto.SOURCE_TYPE_FLOW_DATA_VAR,src_id=1,dst_field=ofproto.OXM_OF_TCP_SRC)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=3,
								priority=96, match=match, instructions=inst)
		datapath.send_msg(mod)


		''' #######################  TAB 4 forward ''' # Controllare Riga 3
		
		# Line 0
		match = ofparser.OFPMatch(in_port=1, metadata = 0, metadata_mask=0x00000000F, ipv4_dst=10.0.0.0/24)
		actions = []
		self.add_flow(datapath=datapath, table_id=4, priority=100,
						match=match, actions=actions)

		# Line 1
		match = ofparser.OFPMatch(in_port=1, metadata = 1, metadata_mask=0x00000000F, ipv4_dst=10.0.0.0/24)
		actions = [ofparser.OFPActionOutput(2)]
		self.add_flow(datapath=datapath, table_id=4, priority=99,
						match=match, actions=actions)

		# Line 2
		match = ofparser.OFPMatch(ipv4_dst=8.0.0.0/24)
		actions = [ofparser.OFPActionOutput(1)]
		self.add_flow(datapath=datapath, table_id=4, priority=98,
						match=match, actions=actions)

		# Line 3
		match = ofparser.OFPMatch(ipv4_dst=10.0.0.0/24)
		actions = [ofparser.OFPActionOutput(2)]
		self.add_flow(datapath=datapath, table_id=4, priority=97,
						match=match, actions=actions)

		# Line 4
		match = ofparser.OFPMatch(in_port=2, ipv4_src=10.0.0.2, tcp_src=80)
		actions = [ofparser.OFPActionSetField(ipv4_src=1.0.0.1),
				   ofparser.OFPActionSetField(tcp_src=80),
				   ofparser.OFPActionOutput(0)]
		self.add_flow(datapath=datapath, table_id=4, priority=96,
						match=match, actions=actions)

		# Line 5
		match = ofparser.OFPMatch(in_port=2, ipv4_src=10.0.0.3, tcp_src=80)
		actions = [ofparser.OFPActionSetField(ipv4_src=1.0.0.1),
				   ofparser.OFPActionSetField(tcp_src=80),
				   ofparser.OFPActionOutput(0)]
		self.add_flow(datapath=datapath, table_id=4, priority=95,
						match=match, actions=actions)

		# Line 6
		match = ofparser.OFPMatch()
		actions = [ofparser.OFPActionOutput(0)]
		self.add_flow(datapath=datapath, table_id=4, priority=94,
						match=match, actions=actions)
