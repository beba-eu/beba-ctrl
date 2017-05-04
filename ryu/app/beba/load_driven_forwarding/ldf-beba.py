import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser

LOG = logging.getLogger('app.openstate.evolution')

UPPER_PORTS = [1,2]
DOWN_PORTS = [3]
LEAVES = [1,2,3]
HOSTS_NUMBER = 1
MAC_ADDRS = ["00:00:00:00:00:01","00:00:00:00:00:02","00:00:00:00:00:03"]


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

		if (datapath.id in LEAVES):
			self.install_leaves(datapath)
		else:
			self.install_spines(datapath)


	def install_leaves(self, datapath): 
		##################################### TABLE 0: DISPATCHING ##################################################

		######################### TABLE 0 CONFIG ###############
		req = bebaparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=0,
				stateful=1)
		datapath.send_msg(req)

		""" Set lookup extractor = {eth_dst} """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_IN_PORT],
				table_id=0)
		datapath.send_msg(req)

		""" Set update extractor = {eth_dst}  """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_IN_PORT],
				table_id=0)
		datapath.send_msg(req)

		""" Field extractor for mpls label """
		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=0,
				extractor_id=0,
				field=ofproto.OXM_OF_MPLS_LABEL)
		datapath.send_msg(req)

		""" Field extractor for timestamp """
		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=0,
				extractor_id=1,
				field=bebaproto.OXM_EXP_TIMESTAMP)
		datapath.send_msg(req)

		""" Packet counter_max for designing probe frequency """
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=0,
				value=9)
		datapath.send_msg(req)

		""" Condition C0: if counter reaches counter_max, then trigger probe sending """ 
		req = bebaparser.OFPExpMsgSetCondition(
				datapath=datapath,
				table_id=0,
				condition_id=0,
				condition=bebaproto.CONDITION_GTE,
				operand_1_fd_id=0,
				operand_2_gd_id=0)
		datapath.send_msg(req)

		req = bebaparser.OFPExpMsgSetCondition(
				datapath=datapath,
				table_id=0,
				condition_id=3,
				condition=bebaproto.CONDITION_GTE,
				operand_1_fd_id=0,
				operand_2_gd_id=0)
		datapath.send_msg(req)


		##################################### TABLE 0 FLOWS ##################################################

		""" RECEIVE PROBE ACTION """
		""" When a probe is received tab0 sends it to tab3"""
		""" match: 	MPLS """
		""" no action """
		""" instruction: goto tab3"""

		match = ofparser.OFPMatch(eth_type=0x8847)
		instructions = [ofparser.OFPInstructionGotoTable(3)]
		mod = ofparser.OFPFlowMod(
			datapath=datapath,
			table_id=0,
			priority=200,
			match=match,
			instructions=instructions)
		datapath.send_msg(mod)

		for i in UPPER_PORTS:
			""" Writes metadata 1 if C0 is true (i.e. if it's time to send probe) to inform the Util Table (2) """
			match = ofparser.OFPMatch(in_port=i, condition0=1)
			actions = [bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUB, output_fd_id=0, operand_1_fd_id=0, operand_2_gd_id=0),
						ofparser.OFPActionPushMpls()] #push mpls for tab 2
			instructions = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
							ofparser.OFPInstructionWriteMetadata(metadata=1, metadata_mask=0xffffffff),
							ofparser.OFPInstructionGotoTable(2)]
			mod = ofparser.OFPFlowMod(
				datapath=datapath,
				table_id=0,
				priority=50,
				match=match,
				instructions=instructions)
			datapath.send_msg(mod)

			""" If C0 is false, update the counter (i++) and go to Util Table for ewma measuring """ 
			match = ofparser.OFPMatch(in_port=i, condition0=0)
			actions = [bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_fd_id=0, operand_1_fd_id=0, operand_2_cost=1)]
			instructions = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions), ofparser.OFPInstructionGotoTable(2)]
			mod = ofparser.OFPFlowMod(
				datapath=datapath,
				table_id=0,
				priority=30,
				match=match,
				instructions=instructions)
			datapath.send_msg(mod)

		""" For packets from down ports (attached to hosts): go to ToR Discovery table (1) """
		for i in DOWN_PORTS:
			match = ofparser.OFPMatch(in_port=i)
			instructions = [ofparser.OFPInstructionGotoTable(1)]
			mod = ofparser.OFPFlowMod(
				datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				instructions=instructions)
			datapath.send_msg(mod)


		for i in [0,1]:
			match = ofparser.OFPMatch(in_port=3, eth_type=0x0800, ip_proto=6, tcp_dst=10000+i)
			actions = [ofparser.OFPActionOutput(i+1)]
			self.add_flow(datapath=datapath, table_id=0, priority=200, match=match, actions=actions)

			match = ofparser.OFPMatch(in_port=3, eth_type=0x0800, ip_proto=6, tcp_src=10000+i)
			actions = [ofparser.OFPActionOutput(i+1)]
			self.add_flow(datapath=datapath, table_id=0, priority=200, match=match, actions=actions)


		######################## TABLE 1 ToR DISCOVERY  #########################################################

		# this cycle writes metadata specifying to which leaf belongs the packet
		for i in LEAVES:
			if (i != datapath.id):
				match=ofparser.OFPMatch(eth_dst=MAC_ADDRS[i-1])
				instructions = [ofparser.OFPInstructionWriteMetadata(metadata=i, metadata_mask=0xffffffff), 
								ofparser.OFPInstructionGotoTable(3)]
				mod = ofparser.OFPFlowMod(
						datapath=datapath,
						table_id=1,
						priority=0,
						match=match,
						instructions=instructions)
				datapath.send_msg(mod)


		######################### TABLE 2: ACTIVE PROBING ######################################################

		################### TABLE 2 CONFIG #########

		req = bebaparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=2,
				stateful=1)
		datapath.send_msg(req)

		""" Set lookup extractor = {IN_PORT} """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_IN_PORT],
				table_id=2)
		datapath.send_msg(req)

		""" Set update extractor = {IN_PORT}  """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_IN_PORT],
				table_id=2)
		datapath.send_msg(req)
		# multiply factor: convert to kbit/s
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=2,
				global_data_variable_id=0,
				value=8000)				
		datapath.send_msg(req)

		# number of averaging samples
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=2,
				global_data_variable_id=3,
				value=40)				
		datapath.send_msg(req)

		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=2,
				extractor_id=1,
				field=bebaproto.OXM_EXP_TIMESTAMP
			)
		datapath.send_msg(req)

		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=2,
				extractor_id=2,
				field=bebaproto.OXM_EXP_PKT_LEN)
		datapath.send_msg(req)

		req = bebaparser.OFPExpMsgSetCondition(
				datapath=datapath,
				condition=bebaproto.CONDITION_GTE,
				condition_id=0,
				table_id=2,
				operand_1_fd_id=4,
				operand_2_gd_id=3)
		datapath.send_msg(req)


		############################### TABLE 2 FLOWS #############################

		""" For every packet coming from spine ports, calculates ewma """
		for i in UPPER_PORTS:
			#simply ewma measuring
			match = ofparser.OFPMatch(in_port=i, condition0=1)
			actions_ewma_1 = [#calculates deltaT: FDV[1]=HF[1]-FDV[0]=TS_NOW - TS_LAST
						bebaparser.OFPExpActionSetDataVariable(table_id=2, opcode=bebaproto.OPCODE_SUB, output_fd_id=1, operand_1_hf_id=1, operand_2_fd_id=0),
						#calculates rate: R = (bytes / deltaT_us) * 1000 kB/s
						bebaparser.OFPExpActionSetDataVariable(table_id=2, opcode=bebaproto.OPCODE_MUL, output_fd_id=2, operand_1_fd_id=2, operand_2_gd_id=0),
						#stores the result in FDV[3]: THE FLOW ESTIMATED RATE
						bebaparser.OFPExpActionSetDataVariable(table_id=2, opcode=bebaproto.OPCODE_DIV, output_fd_id=2, operand_1_fd_id=2, operand_2_fd_id=1),
						#calculates ewma
						bebaparser.OFPExpActionSetDataVariable(table_id=2, opcode=bebaproto.OPCODE_EWMA, output_fd_id=3, operand_1_fd_id=3, operand_2_cost=bebaproto.EWMA_PARAM_0250, operand_3_fd_id=2),
						#saves current timestamp
						bebaparser.OFPExpActionSetDataVariable(table_id=2, opcode=bebaproto.OPCODE_SUM, output_fd_id=0, operand_1_hf_id=1, operand_2_cost=0),
						#counter returns to zero
						bebaparser.OFPExpActionSetDataVariable(table_id=2, opcode=bebaproto.OPCODE_SUB, output_fd_id=4, operand_1_fd_id=4, operand_2_fd_id=4),
						# saves in GDV[i] the ewma
						bebaparser.OFPExpActionSetDataVariable(table_id=2, opcode=bebaproto.OPCODE_SUM, output_gd_id=i, operand_1_fd_id=3, operand_2_cost=0)]
			self.add_flow(datapath=datapath,table_id=2,priority=30,match=match,actions=actions_ewma_1+[ofparser.OFPActionOutput(3)])

			match = ofparser.OFPMatch(in_port=i, condition0=0)
			actions_ewma_2 = [bebaparser.OFPExpActionSetDataVariable(table_id=2, opcode=bebaproto.OPCODE_SUM, output_fd_id=2, operand_1_fd_id=2, operand_2_hf_id=2),
						bebaparser.OFPExpActionSetDataVariable(table_id=2, opcode=bebaproto.OPCODE_SUM, output_fd_id=4, operand_1_fd_id=4, operand_2_cost=1)]
			self.add_flow(datapath=datapath,table_id=2,priority=30,match=match,actions=actions_ewma_2+[ofparser.OFPActionOutput(3)])
			
			""" PROBES: When it matches metadata=1 it means that this packet has to be duplicated to piggyback on it the probe """

			#group mod for packet duplication and probing
			buckets = []
			actions1 = [ofparser.OFPActionSetField(mpls_tc=datapath.id),							   #the GDV[i]
						bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_GLOBAL_DATA_VAR, src_id=i, dst_field=ofproto.OXM_OF_MPLS_LABEL),
						ofparser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
			buckets.append(ofparser.OFPBucket(actions=actions1))

			actions1 = [ofparser.OFPActionSetField(mpls_tc=datapath.id),								#the GDV[other]
						bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_GLOBAL_DATA_VAR, src_id=(1 if i==2 else 2), dst_field=ofproto.OXM_OF_MPLS_LABEL),
						ofparser.OFPActionOutput((1 if i==2 else 2))]
			buckets.append(ofparser.OFPBucket(actions=actions1))

			req = ofparser.OFPGroupMod(datapath=datapath, 
										type_=ofproto.OFPGT_ALL, 
										group_id=i,
										buckets=buckets)
			datapath.send_msg(req)

			# actual match and actions: group action, popMpls() and output(3)
			match = ofparser.OFPMatch(in_port=i, eth_type=0x8847, metadata=1)
			actions = [ofparser.OFPActionGroup(i), ofparser.OFPActionPopMpls(), ofparser.OFPActionOutput(3)]
			self.add_flow(datapath=datapath, table_id=2, priority=100, match=match, actions=actions)


			for j in [0,1]:
				match = ofparser.OFPMatch(in_port=i, eth_type=0x0800, ip_proto=6, tcp_dst=10000+j, condition0=1)
				actions = actions_ewma_1 + [ofparser.OFPActionOutput(3)]
				self.add_flow(datapath=datapath, table_id=2, priority=150, match=match, actions=actions)
			
				match = ofparser.OFPMatch(in_port=i, eth_type=0x0800, ip_proto=6, tcp_src=10000+j, condition0=1)
				actions = actions_ewma_1 + [ofparser.OFPActionOutput(3)]
				self.add_flow(datapath=datapath, table_id=2, priority=150, match=match, actions=actions)
			
				match = ofparser.OFPMatch(in_port=i, eth_type=0x0800, ip_proto=6, tcp_dst=10000+j, condition0=0)
				actions = actions_ewma_2 + [ofparser.OFPActionOutput(3)]
				self.add_flow(datapath=datapath, table_id=2, priority=150, match=match, actions=actions)
			
				match = ofparser.OFPMatch(in_port=i, eth_type=0x0800, ip_proto=6, tcp_src=10000+j, condition0=0)
				actions = actions_ewma_2 + [ofparser.OFPActionOutput(3)]
				self.add_flow(datapath=datapath, table_id=2, priority=150, match=match, actions=actions)


		######################## TABLE 3: FORWARDING ##############################################################

		######################## TABLE 3 CONFIG #####################################################################


		##### GDV[1] contains path utilization to dest 1 on port 1
		##### GDV[2] contains path utilization to dest 2 on port 1
		##### GDV[3] contains path utilization to dest 1 on port 2
		##### GDV[4] contains path utilization to dest 2 on port 2

		req = bebaparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=3,
				stateful=1)
		datapath.send_msg(req)

		""" Set lookup extractor = {ETH_DST IP_PROTO TCP_DST} """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_IPV4_SRC, ofproto.OXM_OF_IPV4_DST, ofproto.OXM_OF_TCP_SRC, ofproto.OXM_OF_TCP_DST],
				table_id=3)
		datapath.send_msg(req)

		""" Set update extractor = {}  """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_IPV4_SRC, ofproto.OXM_OF_IPV4_DST, ofproto.OXM_OF_TCP_SRC, ofproto.OXM_OF_TCP_DST],
				table_id=3)
		datapath.send_msg(req)

		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=3,
				extractor_id=0,
				field=ofproto.OXM_OF_MPLS_LABEL)
		datapath.send_msg(req)

		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=3,
				extractor_id=1,
				field=bebaproto.OXM_EXP_TIMESTAMP
			)
		datapath.send_msg(req)

		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=3,
				extractor_id=2,
				field=bebaproto.OXM_EXP_PKT_LEN)
		datapath.send_msg(req)

		# GDV[0] = multiply factor
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=3,
				global_data_variable_id=0,
				value=8000)				
		datapath.send_msg(req)

		# GDV[6] = packets needed for average
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=3,
				global_data_variable_id=6,
				value=40-1)				
		datapath.send_msg(req)

		# GDV[5] = elephant flow threshold
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=3,
				global_data_variable_id=5,
				value=2000) # 2000 kb/s	
		datapath.send_msg(req)

		# Lower flow threshold
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=3,
				global_data_variable_id=7,
				value=300)				
		datapath.send_msg(req)

		for i in [1,2,3]:
			req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
					datapath=datapath,
					table_id=3,
					global_data_variable_id=i,
					value=0)				
			datapath.send_msg(req)

		#################################### TABLE 3 FLOWS ###################################

		# many conditions as the number of LEAVES-1
		# for i in LEAVES except datapath.id: create condition[i]

		# in the case of 2 Spines. For more spines the configuration becomes more complex
		for destLeaf in [1,2]:
			# C[destinationLeaf]: which port is less utilized? 
			req = bebaparser.OFPExpMsgSetCondition(
					datapath=datapath,
					condition=bebaproto.CONDITION_LTE,
					condition_id=destLeaf,
					table_id=3,
					operand_1_gd_id=destLeaf,
					operand_2_gd_id=destLeaf+2)
			datapath.send_msg(req)

		# C[0], has the flow exceeded threshold? i.e. flow_rate >= threshold => FDV[3] >= GDV[5]
		req = bebaparser.OFPExpMsgSetCondition(
				datapath=datapath,
				condition=bebaproto.CONDITION_GTE,
				condition_id=0,
				table_id=3,
				operand_1_fd_id=3,
				operand_2_gd_id=5)
		datapath.send_msg(req)

		# C[3], is the other flow lower than a value? FDV[4] < GDV[7] ?
		req = bebaparser.OFPExpMsgSetCondition(
				datapath=datapath,
				condition=bebaproto.CONDITION_LTE,
				condition_id=3,
				table_id=3,
				operand_1_fd_id=4,
				operand_2_gd_id=7)
		datapath.send_msg(req)

		# C[4]: did the counter reach counterMax? FDV[5] = GDV[6] ?
		req = bebaparser.OFPExpMsgSetCondition(
				datapath=datapath,
				condition=bebaproto.CONDITION_EQ,
				condition_id=4,
				table_id=3,
				operand_1_fd_id=5,
				operand_2_gd_id=6)
		datapath.send_msg(req)

		# leaf number dependent flows
		if datapath.id==1:
			#LEAF 1 new flows: fetch the destination leaf and check the appropriate condition 
			match1true  = ofparser.OFPMatch(metadata=2, condition1=1, state=0) #dst=2, port 1
			match2true  = ofparser.OFPMatch(metadata=3, condition2=1, state=0) #dst=3, port 1
			match1false = ofparser.OFPMatch(metadata=2, condition1=0, state=0) #dst=2, port 2
			match2false = ofparser.OFPMatch(metadata=3, condition2=0, state=0) #dst=3, port 2
		elif datapath.id==2:
			#LEAF 2 new flows: fetch the destination leaf and check the appropriate condition 
			match1true  = ofparser.OFPMatch(metadata=1, condition1=1, state=0) #dst=1, port 1 
			match2true  = ofparser.OFPMatch(metadata=3, condition2=1, state=0) #dst=3, port 1
			match1false = ofparser.OFPMatch(metadata=1, condition1=0, state=0) #dst=1, port 2
			match2false = ofparser.OFPMatch(metadata=3, condition2=0, state=0) #dst=3, port 2
		elif datapath.id==3:
			#LEAF 3 new flows: fetch the destination leaf and check the appropriate condition 
			match1true  = ofparser.OFPMatch(metadata=1, condition1=1, state=0) #dst=1, port 1
			match2true  = ofparser.OFPMatch(metadata=2, condition2=1, state=0) #dst=2, port 1
			match1false = ofparser.OFPMatch(metadata=1, condition1=0, state=0) #dst=1, port 2
			match2false = ofparser.OFPMatch(metadata=2, condition2=0, state=0) #dst=2, port 2

		#if port 1 is better, set_state(1) and output 1
		actions_true = [bebaparser.OFPExpActionSetState(state=1, table_id=3, idle_timeout=5), ofparser.OFPActionOutput(1)]
		#if port 2 is better, set_state(2) and output 2
		actions_false = [bebaparser.OFPExpActionSetState(state=2, table_id=3, idle_timeout=5), ofparser.OFPActionOutput(2)]

		self.add_flow(datapath=datapath, table_id=3, priority=20, match=match1true,  actions=actions_true)
		self.add_flow(datapath=datapath, table_id=3, priority=20, match=match2true,  actions=actions_true)
		self.add_flow(datapath=datapath, table_id=3, priority=20, match=match1false, actions=actions_false)
		self.add_flow(datapath=datapath, table_id=3, priority=20, match=match2false, actions=actions_false)

		""" extract external probes' data and store in GDVs """

		match = ofparser.OFPMatch(eth_type=0x8847, mpls_tc=datapath.id)
		self.add_flow(datapath=datapath, table_id=3, priority=300, match=match, actions=[])

		for i in UPPER_PORTS:
			for leafNo in LEAVES:
				match = ofparser.OFPMatch(in_port=i, eth_type=0x8847, mpls_tc=leafNo)
				""" actions: save in GDVs external probes' data """
				if datapath.id==1:
					if leafNo==2:
						actions = [bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM, output_gd_id=(1 if i==1 else 3),
																		operand_1_hf_id=0, operand_2_cost=0)]
					elif leafNo==3:
						actions = [bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM, output_gd_id=(2 if i==1 else 4),
																		operand_1_hf_id=0, operand_2_cost=0)]
				elif datapath.id==2:
					if leafNo==1:
						actions = [bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM, output_gd_id=(1 if i==1 else 3),
																		operand_1_hf_id=0, operand_2_cost=0)]
					elif leafNo==3:
						actions = [bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM, output_gd_id=(2 if i==1 else 4),
																		operand_1_hf_id=0, operand_2_cost=0)]
				elif datapath.id==3:
					if leafNo==1:
						actions = [bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM, output_gd_id=(1 if i==1 else 3),
																		operand_1_hf_id=0, operand_2_cost=0)]
					elif leafNo==2:
						actions = [bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM, output_gd_id=(2 if i==1 else 4),
																		operand_1_hf_id=0, operand_2_cost=0)]

				self.add_flow(datapath=datapath, table_id=3, priority=200, match=match, actions=actions)

		for s in UPPER_PORTS:
			for metadata in LEAVES:
				# normal conditions, installed flows continue flowing, calculates ewma if counter reaches max
				match=ofparser.OFPMatch(in_port=3, state=s, metadata=metadata, condition4=1)
				actions_ewma = [#calculates deltaT: FDV[1]=HF[1]-FDV[0]=TS_NOW - TS_LAST
						bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUB, output_fd_id=1, operand_1_hf_id=1, operand_2_fd_id=0),
						#calculates rate: R = (bytes / deltaT_us) * 1000 kB/s
						bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_MUL, output_fd_id=2, operand_1_fd_id=2, operand_2_gd_id=0),
						#stores the result in FDV[3]: THE FLOW ESTIMATED RATE
						bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_DIV, output_fd_id=2, operand_1_fd_id=2, operand_2_fd_id=1),
						#calculates ewma
						bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_EWMA, output_fd_id=3, operand_1_fd_id=3, operand_2_cost=bebaproto.EWMA_PARAM_0250, operand_3_fd_id=2),
						#saves current timestamp
						bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM, output_fd_id=0, operand_1_hf_id=1, operand_2_cost=0),
						#counter returns to zero
						bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUB, output_fd_id=5, operand_1_fd_id=5, operand_2_fd_id=5)]
						
				# FDV[4] = flow's alternative path utilization
				if datapath.id==1:
					if metadata==2:
						actions_ewma += [bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM, output_fd_id=4, 
																		operand_1_gd_id=(1 if s==2 else 3), operand_2_cost=0)]
					elif metadata==3:
						actions_ewma += [bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM, output_fd_id=4, 
																		operand_1_gd_id=(2 if s==2 else 4), operand_2_cost=0)]
				elif datapath.id==2:
					if metadata==1:
						actions_ewma += [bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM, output_fd_id=4, 
																		operand_1_gd_id=(1 if s==2 else 3), operand_2_cost=0)]
					elif metadata==3:
						actions_ewma += [bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM, output_fd_id=4, 
																		operand_1_gd_id=(2 if s==2 else 4), operand_2_cost=0)]
				elif datapath.id==3:
					if metadata==1:
						actions_ewma += [bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM, output_fd_id=4, 
																		operand_1_gd_id=(1 if s==2 else 3), operand_2_cost=0)]
					elif metadata==2:
						actions_ewma += [bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM, output_fd_id=4, 
																		operand_1_gd_id=(2 if s==2 else 4), operand_2_cost=0)]
				actions = actions_ewma + [ofparser.OFPActionOutput(s)]
				self.add_flow(datapath=datapath, table_id=3, priority=30, match=match, actions=actions)
				# normal conditions
				match = ofparser.OFPMatch(in_port=3, state=s, metadata=metadata, condition4=0)
				actions_ewma_bg = [bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM, output_fd_id=2, operand_1_fd_id=2, operand_2_hf_id=2),
							bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM, output_fd_id=5, operand_1_fd_id=5, operand_2_cost=1)]
				actions = actions_ewma_bg + [ofparser.OFPActionOutput(s)]
				self.add_flow(datapath=datapath, table_id=3, priority=30, match=match, actions=actions)

				########### match for extended states: same thing as in normal states but evaluate condition0 ##########
				match = ofparser.OFPMatch(in_port=3, state=s+(1<<5), metadata=metadata, condition0=1, condition4=1)
				actions = actions_ewma + [ofparser.OFPActionOutput(s)]
				self.add_flow(datapath=datapath, table_id=3, priority=35, match=match, actions=actions)

				match = ofparser.OFPMatch(in_port=3, state=s+(1<<5), metadata=metadata, condition0=1, condition4=0)
				actions = actions_ewma_bg + [ofparser.OFPActionOutput(s)]
				self.add_flow(datapath=datapath, table_id=3, priority=35, match=match, actions=actions)

				############# condition[0] and [3] are verified, (i.e. big flow) change port ###########
				match = ofparser.OFPMatch(in_port=3, state=s, condition0=1, condition3=1)
				actions = [bebaparser.OFPExpActionSetState(state=(1 if s==2 else 2)+(1<<5), table_id=3, idle_timeout=5),
							ofparser.OFPActionOutput(1 if s==2 else 2)]
				self.add_flow(datapath=datapath, table_id=3, priority=40, match=match, actions=actions)

				########### if the flow returns to a rate under the threshold #############################
				match = ofparser.OFPMatch(in_port=3, state=s+(1<<5), condition0=0)
				actions = [bebaparser.OFPExpActionSetState(state=s, table_id=3, idle_timeout=5),
							ofparser.OFPActionOutput(s)]
				self.add_flow(datapath=datapath, table_id=3, priority=50, match=match, actions=actions)

	###################### SPINES #################################################################################################


	def install_spines(self, datapath):
		######################### TABLE 1 CONFIG ###############
		req = bebaparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=0,
				stateful=1)
		datapath.send_msg(req)

		""" Set lookup extractor = {eth_dst} """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_IN_PORT],
				table_id=0)
		datapath.send_msg(req)

		""" Set update extractor = {eth_dst}  """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_IN_PORT],
				table_id=0)
		datapath.send_msg(req)

		# multiply factor
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=0,
				value=8000)				
		datapath.send_msg(req)

		# multiply factor
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=1,
				value=40)				
		datapath.send_msg(req)

		# mpls extractor
		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=0,
				extractor_id=0,
				field=ofproto.OXM_OF_MPLS_LABEL
			)
		datapath.send_msg(req)

		# timestamp
		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=0,
				extractor_id=1,
				field=bebaproto.OXM_EXP_TIMESTAMP
			)
		datapath.send_msg(req)

		# packet lenght
		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=0,
				extractor_id=2,
				field=bebaproto.OXM_EXP_PKT_LEN)
		datapath.send_msg(req)

		req = bebaparser.OFPExpMsgSetCondition(
				datapath=datapath,
				condition=bebaproto.CONDITION_GTE,
				condition_id=0,
				table_id=0,
				operand_1_fd_id=4,
				operand_2_gd_id=1)
		datapath.send_msg(req)


		########################### TABLE 1: MEASURING #####################

		for i in LEAVES:
			if i==1:
				out_ports = [6,7]
			elif i==2:
				out_ports = [5,7]
			elif i==3:
				out_ports = [5,6]

			buckets = []
			actions = [bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_GLOBAL_DATA_VAR, src_id=3, dst_field=ofproto.OXM_OF_MPLS_LABEL),
						ofparser.OFPActionOutput(out_ports[0]-4)]
			buckets.append(ofparser.OFPBucket(actions=actions))

			actions = [bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_GLOBAL_DATA_VAR, src_id=4, dst_field=ofproto.OXM_OF_MPLS_LABEL),
						ofparser.OFPActionOutput(out_ports[1]-4)]
			buckets.append(ofparser.OFPBucket(actions=actions))
			
			#send the group action
			req = ofparser.OFPGroupMod(datapath=datapath, 
										type_=ofproto.OFPGT_ALL, 
										group_id=i,
										buckets=buckets)
			datapath.send_msg(req)

			match = ofparser.OFPMatch(in_port=i, eth_type=0x8847)
			actions = [bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_gd_id=3, operand_1_hf_id=0, operand_2_gd_id=out_ports[0]),
						bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_gd_id=4, operand_1_hf_id=0, operand_2_gd_id=out_ports[1]),
						ofparser.OFPActionGroup(i)]
			self.add_flow(datapath=datapath, priority=100, table_id=0, match=match, actions=actions)


			#simple forwarding packets go to second table to forward
			match = ofparser.OFPMatch(in_port=i, condition0=1)
			actions = [#calculates deltaT: FDV[1]=HF[1]-FDV[0]=TS_NOW - TS_LAST
						bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUB, output_fd_id=1, operand_1_hf_id=1, operand_2_fd_id=0),
						#calculates rate: R = (bytes / deltaT_us) * 1000 kB/s
						bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_MUL, output_fd_id=2, operand_1_fd_id=2, operand_2_gd_id=0),
						#stores the result in FDV[3]: THE FLOW ESTIMATED RATE
						bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_DIV, output_fd_id=2, operand_1_fd_id=2, operand_2_fd_id=1),
						#calculates ewma
						bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_EWMA, output_fd_id=3, operand_1_fd_id=3, operand_2_fd_id=2, coeff_3=30),
						#saves current timestamp
						bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_fd_id=0, operand_1_hf_id=1, operand_2_cost=0),
						#counter returns to zero
						bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUB, output_fd_id=4, operand_1_fd_id=4, operand_2_fd_id=4),
						# saves in GDV[i+4] the ewma port[1,2,3]->[5,6,7]
						bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_gd_id=i+4, operand_1_fd_id=3, operand_2_cost=0)]
			instructions = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
							ofparser.OFPInstructionGotoTable(1)]
			mod = ofparser.OFPFlowMod(datapath=datapath, priority=0, table_id=0, match=match, instructions=instructions)
			datapath.send_msg(mod)

			match = ofparser.OFPMatch(in_port=i, condition0=0)
			actions = [bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_fd_id=2, operand_1_fd_id=2, operand_2_hf_id=2),
						bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_fd_id=4, operand_1_fd_id=4, operand_2_cost=1)]
			instructions = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
							ofparser.OFPInstructionGotoTable(1)]
			mod = ofparser.OFPFlowMod(datapath=datapath, priority=0, table_id=0, match=match, instructions=instructions)
			datapath.send_msg(mod)


		######################## TABLE 2: FORWARDING ################

		for i in LEAVES:
			match = ofparser.OFPMatch(eth_dst=MAC_ADDRS[i-1])
			actions = [ofparser.OFPActionOutput(i)]
			self.add_flow(datapath=datapath, table_id=1, priority=0, match=match, actions=actions)