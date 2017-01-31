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
N = 3 # Modificare con valore 3 nei test con topo_5 valore 2 con topo 3

#porta collegata con gli host degli switch edge
HOST_PORT = 1

# MODIFICARE LE FUNZIONI DI EDGE IN MODO CHE NON TOLGONO LA LABEL MPLS SE NO E INUTILE SDOPPIARE RIGHE TAB 4 PER GESTIRE LE 2 CONDIZIONI (PRIMO HOP O NO)
# FATTO

# IN TAB 4
# Problemi con il valore della mpls_label nel pacchetto in ingresso, mpls_label = 1 xke???? forse problema di overflow nella stampa
# solo nella stampa, il valore e' corretto nella label
# SOLUZIONE: fare << 6 nei test :)

# Problema label MPLS, servono 2 stage xke le modifiche siano visibili

# Problema label MPLS anche nella valutazione delle condizioni Tab 1 transport valore aggiornato in tab0 ma visibile in tab 2
# Stesso problema in switch bordo (Rimane cosi)

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
		

		# self.install_edge(datapath)
		if datapath.id == 1 or datapath.id == 6:
			self.install_edge(datapath)
		else:
			if datapath.id == 2:
				self.install_transport_bad(datapath)
			else:
				self.install_transport(datapath)



############################################################ FUNZIONE SWITCH EDGE #######################################################################################

	def install_edge(self, datapath):


		""" Table 0 is stateless """
		""" Set table 1 as stateful solo per usare GD"""	
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
		""" Non mi interessa """ 
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=1)
		datapath.send_msg(req)
 
		""" Non mi interessa """
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


		''' GD[0] = datapath.id<<6 + numero crescente'''
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


		''' HF[1] = OXM_OF_MPLS_TC [pesoArchi] '''
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



		''' HF[1] = OXM_OF_MPLS_TC [pesoArchi] '''
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


		# condition 0: MPLS_TC <= COSTO MEMORIZZATO (FD[0]) ?
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

		# condition 1: MPLS_TC <= 1   --> ovvero e il primo hop ?
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
		# Se il pacchetto proviene da una porta host (HOST_PORT) push label mpls e GOTO Tab 1
		match = ofparser.OFPMatch(in_port = HOST_PORT)
		actions = [ofparser.OFPActionPushMpls()]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(1)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=8, match=match, instructions=inst)
		datapath.send_msg(mod)

		# Se proviene da un'altra porta ha gia la label MPLS GOTO Tab 1 giusto per dirlo esplicitamente perche ci andrebbe da solo CREDO NON DEVO FARE LA PushMpls
		match = ofparser.OFPMatch()
		actions = [] #se proviene da un altra porta ha gia la label MPLS
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(1)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=0, match=match, instructions=inst)
		datapath.send_msg(mod)


		''' #######################  TAB 1 marca il pkt con ID_PKT  '''
		# Setta la label_mpls se non e gia stata configurata con il valore GD[0] + 1 -> (id_switch << 6) + 1
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


		''' #######################  TAB 2 NULLA  serve solo per i bug di OpenFlow, servono 2 stage xke le modifiche MPLS siano visibili'''
		# Non fa niente, ci sta solo per risolvere bug (presunti) di OpenFlow
		match = ofparser.OFPMatch(eth_type=0x8847)
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(3)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=2,
								priority=0, match=match, instructions=inst)
		datapath.send_msg(mod)



		'''####################### TAB 3 Verifica i duplicati, lo stato e' dato da mpls_label'''
		''' somma il costo del link di ingresso al valore memorizzato nel pacchetto mpls_tc + 1 '''
		''' scrive il campo metada = 1 se e' un pacchetto duplicato ovvero nello stato 1 '''
		""" Riga 1 """

		# GD[0] = HF[1] + 1 -> MPLS_TC + 1
		# HF [1] = GD[0] -> MPLS_TC = GD[0]
		# WriteMetadata = 1 -> pacchetto duplicato
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




		""" Riga 2 """

		# GD[0] = HF[1] + 1 -> MPLS_TC + 1
		# HF [1] = GD[0] -> MPLS_TC = GD[0]
		# SetState(1)
		# GOTO Tab 4
		match = ofparser.OFPMatch(state=0, eth_type=0x8847)
		actions = [osparser.OFPExpActionSetDataVariable(table_id=3, opcode=osproto.OPCODE_SUM, output_gd_id=0, operand_1_hf_id=1, operand_2_cost=1),
					osparser.OFPExpActionWriteContextToField(src_type=osproto.SOURCE_TYPE_GLOBAL_DATA_VAR,src_id=0,dst_field=ofproto.OXM_OF_MPLS_TC),					
					# osparser.OFPExpActionSetState(state=1, table_id=3, idle_timeout=15)]
					osparser.OFPExpActionSetState(state=1, table_id=3)]
		inst = [ofparser.OFPInstructionActions(
				ofproto.OFPIT_APPLY_ACTIONS, actions),
				ofparser.OFPInstructionGotoTable(4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=3,
								priority=198, match=match, instructions=inst)
		datapath.send_msg(mod)



		'''# #######################  TAB 4 verifica le condizioni C[0] e C[1]'''
		''' C[0] verifica se il costo memorizzato nel pacchetto e' <= di quello gia conosciuto (in pratica se il pacchetto ha fatto un percorso migliore) '''
		''' C[1] serve semplicemente a capire se e' lo switch direttametne collegato all'host che parla e quindi non bisogna fare il pop della label MPLS '''
		''' le righe BIS verificano la C[1] e non eseguono il POP della label MPLS '''
		''' metadata = 1 e' un pacchetto duplicato quindi DROP '''
		''' nel caso imposta metadata = 3 cioe' non e' un pacchetto duplicato ma il costo e' maggiore di quello conosciuto, inoltro senza aggiornare stato '''

		""" Riga 1 """

		# C[0]: MPLS_TC > COSTO MEMORIZZATO -> HF[1] > FD[0]
		# MetaData: 1 -> Pacchetto duplicato
		# azione DROP
		match = ofparser.OFPMatch(state=1, eth_type=0x8847, condition0=0, metadata = 1)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=4)]
		self.add_flow(datapath=datapath,
				table_id=4,
				priority=1198,
				match=match,
				actions=actions)



		""" Riga 2 """

		# C[0]: MPLS_TC > COSTO MEMORIZZATO -> HF[1] > FD[0]
		# MetaData: 0 -> Pacchetto NON duplicato
		# SetState(1)
		# WriteMetadata = 3 -> pacchetto da percorso peggiore ma NON duplicato
		# azione GOTO Tab 3
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

		""" Riga 2 BIS """

		# C[0]: MPLS_TC > COSTO MEMORIZZATO -> HF[1] > FD[0]
		# MetaData: 0 -> Pacchetto NON duplicato
		# SetState(1)
		# WriteMetadata = 3 -> pacchetto da percorso peggiore ma NON duplicato
		# azione GOTO Tab 3
		match = ofparser.OFPMatch(state=1, eth_type=0x8847, condition0=0, condition1=1, metadata=0)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=4)]
		inst = [ofparser.OFPInstructionActions(
				ofproto.OFPIT_APPLY_ACTIONS, actions),
				ofparser.OFPInstructionWriteMetadata( metadata = 3, metadata_mask = 0xFFFFFFFF ),
				ofparser.OFPInstructionGotoTable(5)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=4,
								priority=198, match=match, instructions=inst)
		datapath.send_msg(mod)


		""" Riga 3 """

		# C[0]: MPLS_TC <= COSTO MEMORIZZATO -> HF[1] <= FD[0]
		# FD[0] = HF[1] -> COSTO MEMORIZZATO = MPLS_TC
		# SetState(1)
		# azione GOTO Tab 3
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

		""" Riga 3 BIS """

		# C[0]: MPLS_TC <= COSTO MEMORIZZATO -> HF[1] <= FD[0]
		# FD[0] = HF[1] -> COSTO MEMORIZZATO = MPLS_TC
		# SetState(1)
		# azione GOTO Tab 3
		match = ofparser.OFPMatch(state=1, eth_type=0x8847, condition0=1, condition1=1)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=4),
					osparser.OFPExpActionSetDataVariable(table_id=4, opcode=osproto.OPCODE_SUM, output_fd_id=0, operand_1_hf_id=1, operand_2_cost=0)]
		inst = [ofparser.OFPInstructionActions(
				 ofproto.OFPIT_APPLY_ACTIONS, actions),
				 ofparser.OFPInstructionGotoTable(5)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=4,
								priority=98, match=match, instructions=inst)
		datapath.send_msg(mod)


		""" Riga 4 """

		# FD[0] = HF[1] -> COSTO MEMORIZZATO = MPLS_TC
		# SetState(1)
		# azione GOTO Tab 3
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

		""" Riga 4 BIS """

		# FD[0] = HF[1] -> COSTO MEMORIZZATO = MPLS_TC
		# SetState(1)
		# azione GOTO Tab 3
		match = ofparser.OFPMatch(state=0, eth_type=0x8847, condition1=1)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=4),
					osparser.OFPExpActionSetDataVariable(table_id=4, opcode=osproto.OPCODE_SUM, output_fd_id=0, operand_1_hf_id=1, operand_2_cost=0)]
		inst = [ofparser.OFPInstructionActions(
				ofproto.OFPIT_APPLY_ACTIONS, actions),
				ofparser.OFPInstructionGotoTable(5)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=4,
								priority=8, match=match, instructions=inst)
		datapath.send_msg(mod)


		'''# #######################  TAB 5  semplicemente MAC Learning '''
		''' Mac Learning ampliato per gestire i metadata = 1 o metadata = 3 '''
		''' metadata = 1 se e' arrivato fin qui significa che il costo nel pacchetto e' minore di quello conosciuto (ha seguito un percorso migliore) AGGIORNARE e DROP'''
		''' metadata = 3 non e' un pacchetto duplicato ma il costo del percorso seguito e' peggiore di quello conosciuto NON AGGIORNARE e INOLTRA '''

		# Per ogni input port, per ogni stato
		for i in range(1, N+1):
			for s in range(N+1):
				match = ofparser.OFPMatch(in_port=i, state=s)
				if s == 0:
					out_port = ofproto.OFPP_FLOOD	#serve la flood, dipende se sto su S1 o S6
				else:
					out_port = s

#				actions = [osparser.OFPExpActionSetState(state=i, table_id=5, hard_timeout=10),
				actions = [osparser.OFPExpActionSetState(state=i, table_id=5),
							ofparser.OFPActionOutput(out_port)]
				self.add_flow(datapath=datapath, table_id=5, priority=0,
								match=match, actions=actions)

			# Configuro le entry con azione DROP per i pacchetti duplicati (con metadata = 1)
			match = ofparser.OFPMatch(in_port=i, metadata = 1)
			# actions = [osparser.OFPExpActionSetState(state=i, table_id=5, hard_timeout=10)]
			actions = [osparser.OFPExpActionSetState(state=i, table_id=5)]
			self.add_flow(datapath=datapath, table_id=5, priority=1198,
							match=match, actions=actions)

		# Per ogni stato
		for s in range(N+1):
			match = ofparser.OFPMatch(state=s, metadata = 3)
			if s == 0:
				out_port = ofproto.OFPP_FLOOD	#serve la flood, dipende se sto su S1 o S6
			else:
				out_port = s

			# Configuro le entry per l'output(in_port) senza aggiornare lo stato
			actions = [ofparser.OFPActionOutput(out_port)]
			self.add_flow(datapath=datapath, table_id=5, priority=198,
							match=match, actions=actions)




############################################################ FUNZIONE SWITCH TRANSPORT #######################################################################################




	def install_transport(self, datapath):



		""" Set table 0 as stateful solo per usare GD, fa le somme del percorso """	
		req = osparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=0,
				stateful=1)
		datapath.send_msg(req)

		""" Ci sta una table NULLA per i bug di OpenFLow con le Label MPLS """

		""" Set table 2 as stateful, verifica le condizioni sul percorso <="""
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
		""" Non mi interessa """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=0)
		datapath.send_msg(req)

		""" Non mi interessa  """
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


		''' HF[1] = OXM_OF_MPLS_TC [pesoArchi] '''
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



		''' HF[1] = OXM_OF_MPLS_TC [pesoArchi] '''
		req = osparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=2,
				extractor_id=1,
				field=ofproto.OXM_OF_MPLS_TC
			)
		datapath.send_msg(req)


		########################### SET CONDITION TAB 2 ############################################


		# condition 3: MPLS_TC <= COSTO MEMORIZZATO (FD[0]) ?
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
		''' somma il costo del link di ingresso al valore memorizzato nel pacchetto mpls_tc + 1 '''
		""" Riga 1 """

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



		''' #######################  TAB 1 NULLA  serve solo per i bug di OpenFlow, servono 2 stage xke le modifiche MPLS siano visibili'''
		# Non fa niente, ci sta solo per risolvere bug (presunti) di OpenFlow
		match = ofparser.OFPMatch(eth_type=0x8847)
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(2)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=1,
								priority=0, match=match, instructions=inst)
		datapath.send_msg(mod)





		'''# #######################  TAB 2 '''
		''' C[0] verifica se il costo memorizzato nel pacchetto e' <= di quello gia conosciuto (in pratica se il pacchetto ha fatto un percorso migliore) '''
		""" Riga 1 """

		# C[0]: MPLS_TC > COSTO MEMORIZZATO -> HF[1] > FD[0]
		# MetaData: 1 -> Pacchetto duplicato
		# azione DROP
		match = ofparser.OFPMatch(state=1, eth_type=0x8847, condition0=0)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=2)]
		self.add_flow(datapath=datapath,
				table_id=2,
				priority=198,
				match=match,
				actions=actions)



		""" Riga 2 """

		# C[0]: MPLS_TC <= COSTO MEMORIZZATO -> HF[1] <= FD[0]
		# FD[0] = HF[1] -> COSTO MEMORIZZATO = MPLS_TC
		# SetState(1)
		# azione GOTO Tab 3
		match = ofparser.OFPMatch(state=1, eth_type=0x8847, condition0=1)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=2),
					osparser.OFPExpActionSetDataVariable(table_id=2, opcode=osproto.OPCODE_SUM, output_fd_id=0, operand_1_hf_id=1, operand_2_cost=0)]
		inst = [ofparser.OFPInstructionActions(
				 ofproto.OFPIT_APPLY_ACTIONS, actions),
				 ofparser.OFPInstructionGotoTable(3)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=2,
								priority=98, match=match, instructions=inst)
		datapath.send_msg(mod)


		""" Riga 3 """

		# FD[0] = HF[1] -> COSTO MEMORIZZATO = MPLS_TC
		# SetState(1)
		# azione GOTO Tab 3
		match = ofparser.OFPMatch(state=0, eth_type=0x8847)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=2),
					osparser.OFPExpActionSetDataVariable(table_id=2, opcode=osproto.OPCODE_SUM, output_fd_id=0, operand_1_hf_id=1, operand_2_cost=0)]
		inst = [ofparser.OFPInstructionActions(
				ofproto.OFPIT_APPLY_ACTIONS, actions),
				ofparser.OFPInstructionGotoTable(3)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=2,
								priority=8, match=match, instructions=inst)
		datapath.send_msg(mod)


		'''# #######################  TAB 3  semplicemente MAC Learning '''

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



		""" Set table 0 as stateful solo per usare GD, fa le somme del percorso """	
		req = osparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=0,
				stateful=1)
		datapath.send_msg(req)

		""" Ci sta una table NULLA per i bug di OpenFLow con le Label MPLS """

		""" Set table 2 as stateful, verifica le condizioni sul percorso <="""
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
		""" Non mi interessa """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=0)
		datapath.send_msg(req)

		""" Non mi interessa  """
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


		''' HF[1] = OXM_OF_MPLS_TC [pesoArchi] '''
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



		''' HF[1] = OXM_OF_MPLS_TC [pesoArchi] '''
		req = osparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=2,
				extractor_id=1,
				field=ofproto.OXM_OF_MPLS_TC
			)
		datapath.send_msg(req)


		########################### SET CONDITION TAB 2 ############################################


		# condition 3: MPLS_TC <= COSTO MEMORIZZATO (FD[0]) ?
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
		''' somma il costo del link di ingresso al valore memorizzato nel pacchetto mpls_tc + 1 '''
		""" Riga 1 """

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



		''' #######################  TAB 1 NULLA  serve solo per i bug di OpenFlow, servono 2 stage xke le modifiche MPLS siano visibili'''
		# Non fa niente, ci sta solo per risolvere bug (presunti) di OpenFlow
		match = ofparser.OFPMatch(eth_type=0x8847)
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(2)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=1,
								priority=0, match=match, instructions=inst)
		datapath.send_msg(mod)





		'''# #######################  TAB 2 '''
		''' C[0] verifica se il costo memorizzato nel pacchetto e' <= di quello gia conosciuto (in pratica se il pacchetto ha fatto un percorso migliore) '''
		""" Riga 1 """

		# C[0]: MPLS_TC > COSTO MEMORIZZATO -> HF[1] > FD[0]
		# MetaData: 1 -> Pacchetto duplicato
		# azione DROP
		match = ofparser.OFPMatch(state=1, eth_type=0x8847, condition0=0)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=2)]
		self.add_flow(datapath=datapath,
				table_id=2,
				priority=198,
				match=match,
				actions=actions)



		""" Riga 2 """

		# C[0]: MPLS_TC <= COSTO MEMORIZZATO -> HF[1] <= FD[0]
		# FD[0] = HF[1] -> COSTO MEMORIZZATO = MPLS_TC
		# SetState(1)
		# azione GOTO Tab 3
		match = ofparser.OFPMatch(state=1, eth_type=0x8847, condition0=1)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=2),
					osparser.OFPExpActionSetDataVariable(table_id=2, opcode=osproto.OPCODE_SUM, output_fd_id=0, operand_1_hf_id=1, operand_2_cost=0)]
		inst = [ofparser.OFPInstructionActions(
				 ofproto.OFPIT_APPLY_ACTIONS, actions),
				 ofparser.OFPInstructionGotoTable(3)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=2,
								priority=98, match=match, instructions=inst)
		datapath.send_msg(mod)


		""" Riga 3 """

		# FD[0] = HF[1] -> COSTO MEMORIZZATO = MPLS_TC
		# SetState(1)
		# azione GOTO Tab 3
		match = ofparser.OFPMatch(state=0, eth_type=0x8847)
		actions = [osparser.OFPExpActionSetState(state=1, table_id=2),
					osparser.OFPExpActionSetDataVariable(table_id=2, opcode=osproto.OPCODE_SUM, output_fd_id=0, operand_1_hf_id=1, operand_2_cost=0)]
		inst = [ofparser.OFPInstructionActions(
				ofproto.OFPIT_APPLY_ACTIONS, actions),
				ofparser.OFPInstructionGotoTable(3)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=2,
								priority=8, match=match, instructions=inst)
		datapath.send_msg(mod)


		'''# #######################  TAB 3  semplicemente MAC Learning '''

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


