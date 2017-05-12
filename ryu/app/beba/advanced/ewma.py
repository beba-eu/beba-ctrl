import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser

LOG = logging.getLogger('app.beba.evolution')


class BebaEvolution(app_manager.RyuApp):

	def __init__(self, *args, **kwargs):
		super(BebaEvolution, self).__init__(*args, **kwargs)

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

		""" switch sent his features, check if Beba supported """
		msg = event.msg
		datapath = msg.datapath

		LOG.info("Configuring switch %d..." % datapath.id)

		""" Set table 0 as stateful """
		req = bebaparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=0,
				stateful=1)
		datapath.send_msg(req)

		""" Set lookup extractor = {eth_dst} """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=0)
		datapath.send_msg(req)

		""" Set update extractor = {eth_dst}  """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=0)
		datapath.send_msg(req)

		###########################################################################################

		""" Set HF[1]=PKT_LEN [byte]"""
		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=0,
				extractor_id=1,
				field=bebaproto.OXM_EXP_PKT_LEN
			)
		datapath.send_msg(req)

		""" Set HF[2]=TIMESTAMP [ms]"""
		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=0,
				extractor_id=2,
				field=bebaproto.OXM_EXP_TIMESTAMP
			)
		datapath.send_msg(req)

		""" GDV[0] = multiply factor for bit/s scale """
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=0,
				value=8)				
		datapath.send_msg(req)



		""" Update function: ewma( [last ewma] , [alpha parameter] , [value to be averaged]) 
        	OUT1 = FDV[0] = count
       	"""
		match = ofparser.OFPMatch()
		actions = [#calculates deltaT: FDV[0]=HF[2]-FDV[0] = TS_NOW - TS_LAST
				   bebaparser.OFPExpActionSetDataVariable(table_id=0, 
				   										  opcode=bebaproto.OPCODE_SUB, 
				   										  output_fd_id=0, 
				   										  operand_1_hf_id=2, 
				   										  operand_2_fd_id=0),
				   #multiply factor: FDV[1] = HF[1] * GD[0] = BYTES * 8000
				   bebaparser.OFPExpActionSetDataVariable(table_id=0, 
				   										  opcode=bebaproto.OPCODE_MUL, 
				   										  output_fd_id=1, 
				   										  operand_1_hf_id=1, 
				   										  operand_2_gd_id=0),
				   #calculates rate: FDV[1]= FD[1]/FDV[0] = (BYTES*8000) / deltaT
				   bebaparser.OFPExpActionSetDataVariable(table_id=0, 
				   										  opcode=bebaproto.OPCODE_DIV, 
				   										  output_fd_id=1, 
				   										  operand_1_fd_id=1, 
				   										  operand_2_fd_id=0),
				   # Calculates EWMA on pkt/s
				   bebaparser.OFPExpActionSetDataVariable(table_id=0, 
												   		  opcode=bebaproto.OPCODE_EWMA, 
												   		  output_fd_id=2, 
												   		  operand_1_fd_id=2, 
												   		  operand_2_cost=bebaproto.EWMA_PARAM_0875,
												   		  operand_3_fd_id=1),
				   #saves last TS: FDV[0] = HF[0] = timestamp  
				   bebaparser.OFPExpActionSetDataVariable(table_id=0, 
				   										  opcode=bebaproto.OPCODE_SUM, 
				   										  output_fd_id=0, 
				   										  operand_1_hf_id=2, 
				   										  operand_2_cost=0),
				   ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)

		""" 
			$ sudo watch --color -n1 dpctl tcp:127.0.0.1:6634 stats-state -c
			mininet> h1 ping h2 -i 0.1 -c 100
			mininet> h1 ping h2 -i 0.05 -c 100
		"""
