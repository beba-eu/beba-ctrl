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

		""" Sampling time """
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=1,
				value=8000)
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


		# Exponentially Weighted Moving Average example
		""" 
			ewma( last_ewma , current_sample , alpha_m ) = (1 - alpha)*current_sample + alpha*(last_ewma) 
			where: 	last_ewma is the previous value of the ewma;
					current_sample is the value of the parameter to be measured at time t;
					alpha_m is the two digit mantissa of the tuning parameter alpha.

			This implementation of the EWMA is a first order IIR filter, stable if 0 < alpha < 1.
		"""

		match = ofparser.OFPMatch()
		actions = [#calculates deltaT: FDV[1]=HF[1]-FDV[0]=TS_NOW - TS_LAST
					bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUB, output_fd_id=1, operand_1_hf_id=1, operand_2_fd_id=0),
					#calculates rate: R = (bytes / deltaT_us) * 8000 [kbps]
					bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_MUL, output_fd_id=2, operand_1_hf_id=2, operand_2_gd_id=1),
					#stores the result in FDV[2]: Flow current rate
					bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_DIV, output_fd_id=2, operand_1_fd_id=2, operand_2_fd_id=1),
					#calculates ewma
					bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_EWMA, output_fd_id=3, operand_1_fd_id=3, operand_2_fd_id=2, coeff_3=30),
					#saves current timestamp
					bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_fd_id=0, operand_1_hf_id=1, operand_2_cost=0),
					ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		self.add_flow(datapath=datapath, priority=0, table_id=0, match=match, actions=actions)
