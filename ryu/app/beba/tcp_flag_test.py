import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofp
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as osp
import ryu.ofproto.beba_v1_0_parser as osparser
import pdb
import time        


LOG = logging.getLogger('app.beba.tcp_flag_test')

class TcpFlagTest(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(TcpFlagTest, self).__init__(*args, **kwargs)
        self.cnt = 0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, event):

        """ Switche sent his features, check if OpenState supported """
        msg = event.msg
        datapath = msg.datapath

        LOG.info("Configuring switch %d..." % datapath.id)

        """ Set table 0 as stateful """
        req = osparser.OFPExpMsgConfigureStatefulTable(
                datapath=datapath,
                table_id=0,
                stateful=1)
        datapath.send_msg(req)

        """ Set lookup extractor = {src ip} """
        req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
                command=osp.OFPSC_EXP_SET_L_EXTRACTOR,
                fields=[ofp.OXM_OF_IPV4_SRC,ofp.OXM_OF_IPV4_DST],
                table_id=0,bit=0)
        datapath.send_msg(req)
        
        """ Set update extractor = {dst ip}  """
        req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
                command=osp.OFPSC_EXP_SET_U_EXTRACTOR,
                fields=[ofp.OXM_OF_IPV4_SRC,ofp.OXM_OF_IPV4_DST],
                table_id=0,bit=0)
        datapath.send_msg(req)

        req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
                command=osp.OFPSC_EXP_SET_U_EXTRACTOR,
                fields=[ofp.OXM_OF_IPV4_DST,ofp.OXM_OF_IPV4_SRC],
                table_id=0,bit=1)
        datapath.send_msg(req)

        # Try to install rule with TCP flag
        LOG.info("Confiuguring Flow table ...")
        match = ofparser.OFPMatch(state=0, eth_type=0x0800,ipv4_src=('10.0.0.0','255.0.0.0'),ip_proto=6,tcp_src=80,tcp_flags=(1,1))
        actions = [osparser.OFPExpActionSetState(state=1, table_id=0, hard_timeout=10,bit=0),
                   osparser.OFPExpActionSetState(state=1, table_id=0, hard_timeout=10,bit=1)]

        inst = [ofparser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        # New state
        match = ofparser.OFPMatch(state=1, eth_type=0x0800,ipv4_src=('10.0.0.0','255.0.0.0'),ip_proto=6,tcp_src=80,tcp_flags=(1,0))
        actions = [osparser.OFPExpActionSetState(state=2, table_id=0, hard_timeout=10), ofparser.OFPActionOutput(2)]

        inst = [ofparser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        # Send a message with 
        mod = osparser.OFPExpStateStatsMultipartRequest(datapath=datapath)
        datapath.send_msg(mod)
        LOG.info("DONE")

    @set_ev_cls(ofp_event.EventOFPExperimenterStatsReply, MAIN_DISPATCHER)
    def state_stats_reply_handler(self, ev):
       #Extract buffer
        tmp_list = osparser.OFPStateStats.parser(ev.msg,0)
        for i in tmp_list:
            out_str = "----> ROUND: " + str(self.cnt) + " PAYLOAD:" + str(i) + " STATE: " + str(i.entry.state) + " KEY: " + str(i.entry.key) + "KEY_CNT: " + str(i.entry.key_count)
            LOG.info(out_str)
        self.cnt = self.cnt + 1
        # Send the message again
        time.sleep(2)
        datapath = ev.msg.datapath
        mod = osparser.OFPExpStateStatsMultipartRequest(datapath=datapath)
        datapath.send_msg(mod)
        
