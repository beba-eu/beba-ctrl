"""
STATEFUL TABLE 0

Lookup-scope=IPV4_DST,IPV4_SRC,UDP_DST,UDP_SRC
Update-scope=IPV4_DST,IPV4_SRC,UDP_DST,UDP_SRC

     _______ 
    |       |--h2
h1--|   S1  |--h3
    |_______|--h4

h1 is the UDP traffic generator
The switch load-balances consistently the UDP flows to h2, h3 and h4

$ ryu-manager forwarding_consistency_1_to_many_UDP.py
$ sudo mn --topo single,4 --switch beba --controller remote --custom beba.py --host=beba --arp --mac
"""

import logging
import struct

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser

LOG = logging.getLogger('app.beba.forwarding_consistency_1_to_many_UDP')

SWITCH_PORTS = 4
LOG.info("Beba Forwarding Consistency sample app initialized")
LOG.info("Supporting MAX %d ports per switch" % SWITCH_PORTS)

class BebaLoadBalancing(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        
        super(BebaLoadBalancing, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        msg = ev.msg
        datapath = msg.datapath

        LOG.info("Configuring switch %d..." % datapath.id)

        """ Set table 0 as stateful """
        req = bebaparser.OFPExpMsgConfigureStatefulTable(datapath=datapath,
                                                         table_id=0,
                                                         stateful=1)
        datapath.send_msg(req)

        """ Set lookup extractor = {ip_src, ip_dst, udp_src, udp_dst} """
        req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                             command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
                                             fields=[ofproto.OXM_OF_IPV4_SRC, ofproto.OXM_OF_IPV4_DST,
                                                     ofproto.OXM_OF_UDP_SRC, ofproto.OXM_OF_UDP_DST],
                                             table_id=0)
        datapath.send_msg(req)

        """ Set update extractor = {ip_src, ip_dst, udp_src, udp_dst} (same as lookup) """
        req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                             command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
                                             fields=[ofproto.OXM_OF_IPV4_SRC, ofproto.OXM_OF_IPV4_DST,
                                                     ofproto.OXM_OF_UDP_SRC, ofproto.OXM_OF_UDP_DST],
                                             table_id=0)
        datapath.send_msg(req)

        """ Group table setup """
        buckets = []
        # Action Bucket: <PWD port_i , SetState(i-1)
        for port in range(2, SWITCH_PORTS+1):
            max_len = 2000
            actions = [bebaparser.OFPExpActionSetState(state=port, table_id=0, idle_timeout=60),
                       ofparser.OFPActionOutput(port=port, max_len=max_len)]

            buckets.append(ofparser.OFPBucket(weight=100,
                                              watch_port=ofproto.OFPP_ANY,
                                              watch_group=ofproto.OFPG_ANY,
                                              actions=actions))

        req = ofparser.OFPGroupMod(datapath=datapath,
                                   command=ofproto.OFPGC_ADD,
                                   type_=ofproto.OFPGT_SELECT,
                                   group_id=1,
                                   buckets=buckets)
        datapath.send_msg(req)

        """ ARP packets flooding """
        match = ofparser.OFPMatch(eth_type=0x0806)
        actions = [ofparser.OFPActionOutput(port=ofproto.OFPP_FLOOD)]
        self.add_flow(datapath=datapath, table_id=0, priority=100,
                      match=match, actions=actions)

        """ Reverse path flow """
        for in_port in range(2, SWITCH_PORTS + 1):
            match = ofparser.OFPMatch(in_port=in_port, eth_type=0x800, ip_proto=17)
            actions = [ofparser.OFPActionOutput(port=1, max_len=0)]                   
            self.add_flow(datapath=datapath, table_id=0, priority=100,
                          match=match, actions=actions)

        """ Forwarding consistency rules"""
        match = ofparser.OFPMatch(in_port=1, state=0, eth_type=0x800, ip_proto=17)
        actions = [ofparser.OFPActionGroup(1)]
        self.add_flow(datapath=datapath, table_id=0, priority=100,
                      match=match, actions=actions)

        for state in range(2,SWITCH_PORTS+1):
            match = ofparser.OFPMatch(in_port=1, state=state, eth_type=0x800, ip_proto=17)
            actions = [ofparser.OFPActionOutput(port=state, max_len=0)]
            self.add_flow(datapath=datapath, table_id=0, priority=100,
                          match=match, actions=actions)
        
    def add_flow(self, datapath, table_id, priority, match, actions):
        inst = [ofparser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table_id,
                                  priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
