import logging
import math
import selective_monitoring
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser

LOG = logging.getLogger('app.beba.simple_monitoring')


class SimpleMonitoring(selective_monitoring.BebaSelectiveMonitoring):
    def __init__(self, *args, **kwargs):
        super(SimpleMonitoring, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.ipsrc = {}  # Dictionary: IP src <->  #states
        self.entropy_ipsrc = []  # Entropy IP src List

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(5)
            entropy = self.entropy(self.ipsrc)
            if (entropy != 0):
                self.entropy_ipsrc.append(entropy)
                LOG.info(self.entropy_ipsrc)
            if (len(self.entropy_ipsrc) >= 6):  # Wait 30s before starting  the detection
                self.detection(self.entropy_ipsrc, self.ipsrc)
            self.ipsrc.clear()  # Remove all entries in the dictionary

    def entropy(self, dictionary):
        total_states = 0
        entropy = 0
        p = 0

        for index in dictionary:
            total_states += dictionary[index]
        for index in dictionary:
            p = float(dictionary[index]) / total_states
            entropy += -p * math.log(p, 2)
        return round(entropy, 5)

    def detection(self, entropylist, dictionary):
        global threshold_min
        if (len(entropylist) == 6):  # Get the entropy of the network under normal conditions during a 30sec window
            threshold_average = sum(entropylist) / len(entropylist)
            threshold_min = min(entropylist)
        else:
            if (entropylist[-1] < threshold_min):
                attackerIp = ((max(dictionary, key=dictionary.get))[1:-1]).replace(", ", ".")
                LOG.info('******* DDoS Flooding  DETECTED *******')
                LOG.info('Infected Host: %s', attackerIp)
                for dp in self.datapaths.values():
                    self.mitigation(dp, attackerIp, 0)

    def mitigation(self, datapath, ipadress, tableid):
        match = ofparser.OFPMatch(eth_type=0x0800, ipv4_src=ipadress)
        actions = []
        self.add_flow(datapath=datapath, table_id=tableid, priority=100,
                      match=match, actions=actions)

    def _request_stats(self, datapath):
        req = bebaparser.OFPExpStateStatsMultipartRequestAndDelete(datapath, table_id=0)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPExperimenterStatsReply, MAIN_DISPATCHER)
    def _state_stats_reply_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        if (msg.body.experimenter == 0XBEBABEBA):
            if (msg.body.exp_type == bebaproto.OFPMP_EXP_STATE_STATS_AND_DELETE):
                state_stats_list = bebaparser.OFPStateStats.parser(msg, 0)
                if (state_stats_list != 0):
                    for index in range(len(state_stats_list)):
                        if (state_stats_list[index].entry.state != 0):
                            self.ipsrc[str(state_stats_list[index].entry.key)] = state_stats_list[index].entry.state
                else:
                    LOG.info("No data")
        # Print the state stats
        if (len(self.ipsrc) != 0):
            LOG.info('****************************')
        for index in self.ipsrc:
            LOG.info('IP_SRC=%s State=%s', index, self.ipsrc[index])
