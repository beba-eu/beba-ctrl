import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofp
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser
import array
import struct


LOG = logging.getLogger('app.beba.maclearning.state_sync')

# Number of switch ports
N = 4

LOG.info("Support max %d ports per switch" % N)

devices=[]

class OSMacLearning(app_manager.RyuApp):

	def __init__(self, *args, **kwargs):
		super(OSMacLearning, self).__init__(*args, **kwargs)

	def add_flow(self, datapath, table_id, priority, match, actions):
		if len(actions) > 0:
			inst = [ofparser.OFPInstructionActions(
					ofp.OFPIT_APPLY_ACTIONS, actions)]
		else:
			inst = []
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table_id,
								priority=priority, match=match, instructions=inst)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, event):

		""" Switche sent his features, check if Beba supported """
		msg = event.msg
		datapath = msg.datapath
		devices.append(datapath)
	

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
				fields=[ofp.OXM_OF_ETH_DST],
				table_id=0)
		datapath.send_msg(req)

		""" Set update extractor = {eth_src}  """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofp.OXM_OF_ETH_SRC],
				table_id=0)
		datapath.send_msg(req)

		# for each input port, for each state
		for i in range(1, N+1):
			for s in range(N+1):
				match = ofparser.OFPMatch(in_port=i, state=s)
				if s == 0:
					out_port = ofp.OFPP_FLOOD
				else:
					out_port = s
				actions = [
					bebaparser.OFPExpActionSetState(state=i, table_id=0, hard_timeout=10),
					ofparser.OFPActionOutput(out_port)
					#,ofparser.OFPActionOutput(ofp.OFPP_CONTROLLER,
					#ofp.OFPCML_NO_BUFFER)
				]

				self.add_flow(datapath=datapath, table_id=0, priority=0, match=match, actions=actions)
				
	#State Sync: Parse the response
	@set_ev_cls(ofp_event.EventOFPExperimenterStatsReply, MAIN_DISPATCHER)
	def packet_in_handler(self, event):
		msg = event.msg
		
		if (msg.body.experimenter == 0xBEBABEBA):
			if(msg.body.exp_type == bebaproto.OFPMP_EXP_STATE_STATS):
				state_entry_list = bebaparser.OFPStateStats.parser(msg.body.data)
				if (state_entry_list==[]):
					print "No key for this state"
				else:
					for state_entry in state_entry_list:
						print 'State :',state_entry.entry.state
						print 'Key   :',bebaparser.state_entry_key_to_str(state_entry)
						print 'FDV   :', state_entry.entry.flow_data_var
						print '*********'

import time
from threading import Thread

def ask_for_state(t, k, state):
	""" 
	State Sync: Get the flows in a given state
	"""

	counter = 0
	while counter < k:
		time.sleep(t)
		if devices==[]:
			print ("No connected device")
		else:
			# State Sync: Ask for flows in the state 'state'
			m = bebaparser.OFPExpGetFlowsInState(devices[0], table_id=0, state=state)
			devices[0].send_msg(m)
			print("GetFlowsInState message sent")

		counter = counter + 1

state = 2

# Thread that asks 5 times for flows in the above state, interval between messages is 5 sec
t = Thread(target=ask_for_state, args=(5, 5, state))
t.start()

