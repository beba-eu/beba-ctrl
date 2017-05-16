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
import binascii

LOG = logging.getLogger('app.beba.maclearning.state_sync')

# Number of switch ports
N = 4

LOG.info("Support max %d ports per switch" % N)

devices = []

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

        """ Switch sent his features, check if Beba supported """
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

        # the counter is stored in global_data_vars[0]
        req = bebaparser.OFPExpMsgsSetGlobalDataVariable(datapath=datapath, table_id=0, global_data_variable_id=0,
                                                         value=0)
        datapath.send_msg(req)

        # for each input port, for each state
        for i in range(1, N + 1):
            for s in range(N + 1):
                match = ofparser.OFPMatch(in_port=i, state=s)
                if s == 0:
                    out_port = ofp.OFPP_FLOOD
                else:
                    out_port = s

                actions = [
                    # for each packet forwarded by the switch global_data_vars[0]+=1
                    bebaparser.OFPExpActionSetDataVariable(table_id=0,
                                                           opcode=bebaproto.OPCODE_SUM,
                                                           output_gd_id=0,
                                                           operand_1_gd_id=0,
                                                           operand_2_cost=1),
                    bebaparser.OFPExpActionSetState(state=i, table_id=0,hard_timeout=10),
                    ofparser.OFPActionOutput(out_port)]
                self.add_flow(datapath=datapath, table_id=0, priority=0, match=match, actions=actions)

    # State Sync: parse respond message from switch
    @set_ev_cls(ofp_event.EventOFPExperimenterStatsReply, MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        msg = event.msg
        reply = msg.body
        if (reply.experimenter == 0xBEBABEBA):
            if msg.body.exp_type == bebaproto.OFPMP_EXP_GLOBAL_DATA_STATS:
                global_data_list = bebaparser.OFPGlobalDataStats.parser(msg.body.data)
                for index, global_data in enumerate(global_data_list):
                    # Only global_data_vars[0] is interesting to print
                    if index == 0:
                        print("global data %d = %d" % (index,global_data.value))
                print('*' * 42)

import time
from threading import Thread

def ask_for_global_data_vars():
    """ State Sync: Get the global_data_vars from the first switch"""
    while True:
        time.sleep(10)
        if devices == []:
            print("No connected device")
        else:
            # State Sync: Message that asks for the global data vars from table 0 of the first datapath element
            msg = bebaparser.OFPExpGlobalDataStatsMultipartRequest(devices[0], table_id=0)
            devices[0].send_msg(msg)
            print("OFPExpGlobalDataStatsMultipartRequest sent")

t = Thread(target=ask_for_global_data_vars, args=())
t.start()