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
			self.function_lan_dmz_isolation(datapath)

	'''########################################################################################################################################################## 
	############################################################################################################################################################# 
	##########################################################                            ####################################################################### 
	########################################################## FUNZIONE LAN/DMZ ISOLATION ####################################################################### 
	##########################################################                            ####################################################################### 
	##########################################################################################################################################################''' 
	# NECESSARIE TAB 0, 4
	# TAB 0, 4 CONFIGURATE IN QUESTA FUNZIONE


	def function_lan_dmz_isolation(self, datapath):

		""" Set table 0 as stateful """	
		req = bebaparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=0,
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

		""" Tab4 """
		""" Stateless """

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



		################################# REGOLE ############################################

		# Line ARP
		match = ofparser.OFPMatch(eth_type=0x0806)#metadata = (1 , 0x000000001))
		actions = [ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=100, match=match, instructions=inst)
		datapath.send_msg(mod)


		''' #######################  TAB 0  '''  # tutto ok, controllare 11 (sta nella funzione dopo)
		# Line 0
		match = ofparser.OFPMatch(state=0, in_port=DMZ_PORT, eth_type=0x0800, ipv4_dst=('10.0.0.0','255.255.255.0'))
		actions = [bebaparser.OFPExpActionSetState(state=11, table_id=0)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionWriteMetadata(metadata=0, metadata_mask=0xFFFFFFFF),
			ofparser.OFPInstructionGotoTable(4)]
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

		# Line 2
		match = ofparser.OFPMatch(state=11, in_port=DMZ_PORT, eth_type=0x0800, ipv4_dst=('10.0.0.0','255.255.255.0'))
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionWriteMetadata(metadata=0, metadata_mask=0xFFFFFFFF),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=98, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 3
		match = ofparser.OFPMatch(state=11, in_port=LAN_PORT, eth_type=0x0800, ipv4_dst=('8.0.0.0','255.255.255.0'))
		actions = [bebaparser.OFPExpActionSetState(state=2, table_id=0)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionWriteMetadata(metadata=1, metadata_mask=0xFFFFFFFF),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=97, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 4
		match = ofparser.OFPMatch(state=12, in_port=LAN_PORT, eth_type=0x0800, ipv4_dst=('8.0.0.0','255.255.255.0'))
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionWriteMetadata(metadata=0, metadata_mask=0xFFFFFFFF),
			ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=96, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Line 5
		match = ofparser.OFPMatch(state=12, in_port=DMZ_PORT, eth_type=0x0800, ipv4_dst=('10.0.0.0','255.255.255.0'))
		actions = [bebaparser.OFPExpActionSetState(state=2, table_id=0)]
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


		''' #######################  TAB 1 estrae la porta  ''' 
		# NON MI INTERESSA PER QUESTO CASO D USO


		''' #######################  TAB 2 restore'''
		# NON MI INTERESSA PER QUESTO CASO D USO


		''' #######################  TAB 3 translate ''' 
		# NON MI INTERESSA PER QUESTO CASO D USO


		''' #######################  TAB 4 forward ''' 
		
		# Line 0
		match = ofparser.OFPMatch(in_port=DMZ_PORT, metadata = (0 , 0x00000000F), eth_type=0x0800, ipv4_dst=('10.0.0.0','255.255.255.0'))
		actions = []
		self.add_flow(datapath=datapath, table_id=4, priority=100,
						match=match, actions=actions)


		# Line 1 MOD Con modifca MAC
		match = ofparser.OFPMatch(in_port=DMZ_PORT, metadata = (1 , 0x00000000F), eth_type=0x0800, ipv4_dst='10.0.0.2')
		actions = [ofparser.OFPActionSetField(eth_dst="00:00:00:00:00:03"),
					ofparser.OFPActionOutput(LAN_PORT)]
		self.add_flow(datapath=datapath, table_id=4, priority=99,
						match=match, actions=actions)

		# Line 1 BIS MOD Con modifca MAC
		match = ofparser.OFPMatch(in_port=DMZ_PORT, metadata = (1 , 0x00000000F), eth_type=0x0800, ipv4_dst='10.0.0.3')
		actions = [ofparser.OFPActionSetField(eth_dst="00:00:00:00:00:04"),
					ofparser.OFPActionOutput(LAN_PORT)]
		self.add_flow(datapath=datapath, table_id=4, priority=99,
						match=match, actions=actions)


		# Line 2 MOD Con modifca MAC
		match = ofparser.OFPMatch(eth_type=0x0800, ipv4_dst='8.0.0.2')
		actions = [ofparser.OFPActionSetField(eth_dst="00:00:00:00:00:02"),
					ofparser.OFPActionOutput(DMZ_PORT)]
		self.add_flow(datapath=datapath, table_id=4, priority=98,
						match=match, actions=actions)


		# Line 3 MOD Con modifica MAC BIS
		match = ofparser.OFPMatch(eth_type=0x0800, ipv4_dst='10.0.0.2')
		actions = [ofparser.OFPActionSetField(eth_dst="00:00:00:00:00:03"),
					ofparser.OFPActionOutput(LAN_PORT)]
		self.add_flow(datapath=datapath, table_id=4, priority=97,
						match=match, actions=actions)

		# Line 3 BIS MOD Con modifica MAC BIS
		match = ofparser.OFPMatch(eth_type=0x0800, ipv4_dst='10.0.0.3')
		actions = [ofparser.OFPActionSetField(eth_dst="00:00:00:00:00:04"),
					ofparser.OFPActionOutput(LAN_PORT)]
		self.add_flow(datapath=datapath, table_id=4, priority=97,
						match=match, actions=actions)


	def install_forward(self, datapath):

		match = ofparser.OFPMatch()#metadata = (1 , 0x000000001))
		actions = [ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=10, match=match, instructions=inst)
		datapath.send_msg(mod)