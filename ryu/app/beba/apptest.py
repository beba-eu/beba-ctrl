import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0  as bebaproto 		# LUCA da sistemare cosi e brutto
import ryu.ofproto.beba_v1_0_parser as bebaparser 

LOG = logging.getLogger('app.openstate.maclearning')

# Number of switch ports
N = 4

LOG.info("Support max %d ports per switch" % N)

class OpenStateMacLearning(app_manager.RyuApp):

	def __init__(self, *args, **kwargs):
		super(OpenStateMacLearning, self).__init__(*args, **kwargs)

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

		""" Set table 0 as stateful """
		req = bebaparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=0,
				stateful=1)
		datapath.send_msg(req)

		""" Set table 1 as stateful """
		req = bebaparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=1,
				stateful=1)
		datapath.send_msg(req)


	############################### LOOKUP/UPDATE ################

		""" Set lookup extractor = {eth_dst} """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_IPV4_DST, ofproto.OXM_OF_ETH_DST],
				table_id=0)
		datapath.send_msg(req)

		""" Set update extractor = {eth_src}  """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_IPV4_DST,ofproto.OXM_OF_ETH_SRC],
				table_id=0)
		datapath.send_msg(req)


		""" Set lookup extractor = {eth_dst} """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=1)
		datapath.send_msg(req)

		""" Set update extractor = {eth_src}  """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=1)
		datapath.send_msg(req)

	########################### SET GD DATA VARIABLE ############################################

		# req = bebaparser.OFPExpMsgHeaderFieldExtract(
		# 		datapath=datapath,
		# 		table_id=0,
		# 		extractor_id=0,
		# 		field=ofproto.OXM_OF_IPV4_SRC
		# 	)
		# datapath.send_msg(req)

		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=0,
				value=313
			)
		datapath.send_msg(req)

		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=2,
				value=22
			)
		datapath.send_msg(req)

		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=4,
				value=44
			)
		datapath.send_msg(req)

		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=5,
				value=55
			)
		datapath.send_msg(req)


########################### SET GD DATA VARIABLE ############################################

		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=1,
				global_data_variable_id=3,
				value=55
			)
		datapath.send_msg(req)

		########################### SET HF DATA VARIABLE TAB 1 ############################################
		# SI PUO FARE???


		# ''' HF[0] = OXM_OF_METADATA [id_pkt] '''
		# req = bebaparser.OFPExpMsgHeaderFieldExtract(
		# 		datapath=datapath,
		# 		table_id=1,
		# 		extractor_id=0,
		# 		field=ofproto.OXM_OF_METADATA
		# 	)
		# datapath.send_msg(req)

		''' HF[0] = OXM_OF_METADATA [id_pkt] '''
		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=1,
				extractor_id=0,
				field=bebaproto.OXM_EXP_STATE
			)
		datapath.send_msg(req)



		''' #######################  TAB 0 NULLA  serve solo per i bug di OpenFlow, servono 2 stage xke le modifiche MPLS siano visibili'''
		# Non fa niente, ci sta solo per risolvere bug (presunti) di OpenFlow
		# match = ofparser.OFPMatch(condition0=0)
		# actions = [bebaparser.OFPExpActionSetState(state=1, table_id=0),
		# 			ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		# inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
		# mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
		# 						priority=0, match=match, instructions=inst)
		# datapath.send_msg(mod)

		# match = ofparser.OFPMatch()#condition0=1)
		# actions = [bebaparser.OFPExpActionSetState(state=1, table_id=0),
		# 			bebaparser.OFPExpActionSetDataVariable(table_id=0, port_id=1, opcode=bebaproto.OPCODE_SUM, output_mem_pd_id=0, operand_1_mem_pd_id=1, operand_2_mem_pd_id=1),
		# 			# bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_GLOBAL_DATA_VAR,src_id=0,dst_field=ofproto.OXM_OF_MPLS_LABEL),
		# 			bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_gd_id=3, operand_1_hf_id=0, operand_2_cost=0),
		# 			ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		# inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
		# mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
		# 						priority=0, match=match, instructions=inst)
		# datapath.send_msg(mod)


		match = ofparser.OFPMatch()
		actions = [bebaparser.OFPExpActionSetState(state=1, table_id=0),
					# bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_fd_id=1, operand_1_hf_id=0, operand_2_cost=3)]
					# bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_fd_id=2, operand_1_gd_id=0, operand_2_gd_id=2)]
					bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_GLOBAL_DATA_VAR,src_id=0,dst_field=ofproto.OXM_OF_METADATA)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
				# ofparser.OFPInstructionWriteMetadata(metadata=13, metadata_mask=0xFFFFFFFF),
				ofparser.OFPInstructionGotoTable(1)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=0, match=match, instructions=inst)
		datapath.send_msg(mod)


		''' #######################  TAB 1   '''


		match = ofparser.OFPMatch(state=2)
		actions = [bebaparser.OFPExpActionSetState(state=2, table_id=1),
					bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=1, operand_1_hf_id=0, operand_2_cost=10),
					ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
					# bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_gd_id=0, operand_1_gd_id=1, operand_2_cost=3)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=1,
								priority=10, match=match, instructions=inst)
		datapath.send_msg(mod)


		match = ofparser.OFPMatch(metadata=313)
		actions = [bebaparser.OFPExpActionSetState(state=2, table_id=1),
					bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_gd_id=0, operand_1_gd_id=3, operand_2_cost=3)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=1,
								priority=0, match=match, instructions=inst)
		datapath.send_msg(mod)


		# # for each input port, for each state
		# for i in range(1, N+1):
		# 	for s in range(N+1):
		# 		match = ofparser.OFPMatch(in_port=i, state=s)
		# 		if s == 0:
		# 			out_port = ofproto.OFPP_FLOOD
		# 		else:
		# 			out_port = s
		# 		actions = [bebaparser.OFPExpActionSetState(state=i, table_id=0, hard_timeout=10),
		# 					ofparser.OFPActionOutput(out_port)]
		# 		self.add_flow(datapath=datapath, table_id=0, priority=0,
		# 						match=match, actions=actions)

		""" Need to drop some packets for DEMO puporses only (avoid learning before manual send_eth)"""
		#ARP packets
		# LOG.info("WARN: ARP packets will be dropped on switch %d" % datapath.id)
		# match = ofparser.OFPMatch(eth_type=0x0806)
		# actions = []
		# self.add_flow(datapath=datapath, table_id=0, priority=100,
		# 				match=match, actions=actions)

		#IPv6 packets
		# #LOG.info("WARN: IPv6 packets will be dropped on switch %d" % datapath.id)
		# match = ofparser.OFPMatch(eth_type=0x86dd)
		# actions = []
		# self.add_flow(datapath=datapath, table_id=0, priority=100,
		# 				match=match, actions=actions)

