import logging
import selective_monitoring_1
import math
import time
import csv
from ryu.lib.packet import ether_types, in_proto
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser
import datetime

LOG = logging.getLogger('app.beba.simple_monitoring_1')
timewindow = 4
precision = 3  # 1 -> small precision 68% / 2 -> medium precision 95% / 3 -> high precision 99,7%


class SimpleMonitoring_1(selective_monitoring_1.BebaSelectiveMonitoring_1):
    def __init__(self, *args, **kwargs):
        super(SimpleMonitoring_1, self).__init__(*args, **kwargs)
        self.monitor_thread = hub.spawn(self._monitor)
        self.entropy_ipsrc, self.entropy_ipdst, self.entropy_portsrc, self.entropy_portdst, self.abscisse_time = ([] for i in range(5)) # Entropy Lists
        self.datapaths, self.ipsrc, self.ipdst, self.portsrc, self.portdst, self.tcp_portsrc, self.tcp_portdst, self.udp_portsrc, self.udp_portdst = ({} for i in range(9)) # Datapath + Features dictionaries
        # External files to store calculated values
        with open('entropy.csv', 'wb') as csvfile:  # Set the header and Empty the file
            writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(
                ["Time (s)", " IP Src Entropy", " IP Dst Entropy", " Port Src Entropy", " Port Dst Entropy"])
            csvfile.close()
        with open('counters.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile, delimiter=';', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(
                ["Time (s)", " IPsrc", " State", " IPdst", " State", " Portsrc", " State", " Portdst", " State"])
            csvfile.close()
        open('counter_ip_src.csv', 'wb').close()
        open('counter_ip_dst.csv', 'wb').close()
        open('counter_port_src.csv', 'wb').close()
        open('counter_port_dst.csv', 'wb').close()
        self.timer = 1
        self.replies = 0

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
            # Send the states requests to the state tables
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(timewindow)  # Wait X seconds
            self.replies = 0

    def mean(self, mylist):
        return float(sum(mylist)) / len(mylist) if len(mylist) > 0 else float('nan')

    def variance(self, mylist):
        xmean = self.mean(mylist)
        return self.mean([(x - xmean) ** 2 for x in mylist])

    def entropy(self, dictionary):
        total_states = 0
        entropy = 0
        p = 0

        for index in dictionary:
            total_states += dictionary[index]
        if (total_states != 1 and len(dictionary) != 1):  # Division by 0
            for index in dictionary:
                p = float(dictionary[index]) / total_states
                entropy += (-p * math.log(p, 2)) / (math.log(len(dictionary), 2))  # Normalized entropy
            return round(entropy, 5)
        else:
            return 0

    def detection(self):
        # No threats
        attack_type = mitigation_type = i = 0
        victim_address, victim_port, attacker_address, attacker_port, proto_src, proto_dst = ([] for i in range(6))

        # Entropy IP/Port DST variance calculation for the Statistic Gauss's law limits  
        variance_entropy_ipdst = self.variance(self.entropy_ipdst[:-1])
        variance_entropy_ipsrc = self.variance(self.entropy_ipsrc[:-1])
        variance_entropy_portdst = self.variance(self.entropy_portdst[:-1])

        # DDoS Detection (normal values are in the [meanx-precision*sigma;meanx+precision*sigma] range, if NOT -> Attack!)
        if ((self.mean(self.entropy_ipdst[:-1]) - precision * (variance_entropy_ipdst ** 0.5) > self.entropy_ipdst[-1])
            and (self.mean(self.entropy_portdst[:-1]) - precision * (variance_entropy_portdst ** 0.5) >
                     self.entropy_portdst[-1])):

            LOG.info('\033[91m******* (D)DoS Flooding  DETECTED *******\033[0m')
            LOG.info('\033[91m******* Time: ' + str(datetime.datetime.now().time()) + ' *******\033[0m')
            mitigation_type = 1
            attack_type = 1

        # DoS ICMP FLOODING Detection
        elif (
            (self.mean(self.entropy_ipdst[:-1]) - precision * (variance_entropy_ipdst ** 0.5) > self.entropy_ipdst[-1])
        and (self.mean(self.entropy_ipsrc[:-1]) - precision * (variance_entropy_ipsrc ** 0.5) > self.entropy_ipsrc[
            -1])):

            LOG.info('\033[91m******* DoS ICMP Flooding  DETECTED *******\033[0m')
            LOG.info('\033[91m******* Time: ' + str(datetime.datetime.now().time()) + ' *******\033[0m')
            mitigation_type = 1
            attack_type = 3

        # DDoS ICMP FLOODING Detection
        elif (
            (self.mean(self.entropy_ipdst[:-1]) - precision * (variance_entropy_ipdst ** 0.5) > self.entropy_ipdst[-1])
        and (self.mean(self.entropy_ipsrc[:-1]) + precision * (variance_entropy_ipsrc ** 0.5) < self.entropy_ipsrc[
            -1])):

            LOG.info('\033[91m******* DDoS ICMP Flooding  DETECTED *******\033[0m')
            LOG.info('\033[91m******* Time: ' + str(datetime.datetime.now().time()) + ' *******\033[0m')
            mitigation_type = 1
            attack_type = 4

        # PortScan detection
        elif (
            (self.mean(self.entropy_ipdst[:-1]) - precision * (variance_entropy_ipdst ** 0.5) > self.entropy_ipdst[-1])
        and (self.mean(self.entropy_portdst[:-1]) + precision * (variance_entropy_portdst ** 0.5) <
                 self.entropy_portdst[-1])):

            LOG.info('\033[91m******* PortScan  DETECTED *******\033[0m')
            LOG.info('\033[91m******* Time: ' + str(datetime.datetime.now().time()) + ' *******\033[0m')
            mitigation_type = 1
            attack_type = 2

        # Extract information about the attack
        if (mitigation_type != 0):
            # Victims information:
            # IPs
            variance_IPdst = self.variance((self.ipdst).values())
            for index in self.ipdst:  # Store the IP values greater than the mean+sigma limit
                if (self.mean((self.ipdst).values()) + precision * (variance_IPdst ** 0.5) < self.ipdst[index]):
                    victim_address.append(index)

            # Ports
            if (attack_type == 1):  # if not a portscan attack or ICMP Flooding
                variance_Portdst = self.variance((self.portdst).values())
                for index in self.portdst:
                    if (self.mean((self.portdst).values()) + precision * (variance_Portdst ** 0.5) < self.portdst[
                        index]):
                        victim_port.append(index)
                # Protocols <-> Ports
                for port in victim_port:
                    if port in self.tcp_portdst and port in self.udp_portdst:
                        if (self.tcp_portdst[port] > self.udp_portdst[port]):
                            proto_dst.append(6)
                        elif (self.tcp_portdst[port] == self.udp_portdst[port]):
                            proto_dst.append(0)
                        else:
                            proto_dst.append(17)
                    elif port in self.tcp_portdst:
                        proto_dst.append(6)
                    elif port in self.udp_portdst:
                        proto_dst.append(17)

            # Printing the Victims' information:
            for ip in victim_address:
                LOG.info('\033[93m** Victim Host: %s **\033[0m', ip)
            for port in victim_port:
                LOG.info('\033[93m** Victim Portdst: %s **\033[0m', port)

                # Attackers information:
            variance_IPsrc = self.variance((self.ipsrc).values())
            for index in self.ipsrc:  # Store the IP values that are greater than the mean+sigma limit
                if (self.mean((self.ipsrc).values()) + precision * (variance_IPsrc ** 0.5) < self.ipsrc[index]):
                    attacker_address.append(index)
            if (len(attacker_address) != 0):
                mitigation_type = 2

            # Spoofed Ports Src ? and NOT AN ICMP FLOODING ATTACK
            # if (((self.entropy_portsrc[-2]-self.entropy_portsrc[-1])<0) and (attack_type != 3 and attack_type != 4)):
            #     LOG.info('\033[91m** SPOOFED Port Src **\033[0m')
            if (attack_type != 3 and attack_type != 4):
                variance_Portsrc = self.variance((self.portsrc).values())
                for index in self.portsrc:  # Store the Port values that are greater than the mean+sigma limit
                    if (self.mean((self.portsrc).values()) + precision * (variance_Portsrc ** 0.5) < self.portsrc[
                        index]):
                        attacker_port.append(index)
                # Protocols <-> Ports
                for port in attacker_port:  # For each port store also the protocol type (needed to send the OF rule)
                    if port in self.tcp_portsrc and port in self.udp_portsrc:
                        if (self.tcp_portsrc[port] > self.udp_portsrc[port]):
                            proto_src.append(6)
                        elif (self.tcp_portsrc[port] == self.udp_portsrc[port]):
                            proto_src.append(0)
                        else:
                            proto_src.append(17)
                    elif port in self.tcp_portsrc:
                        proto_src.append(6)
                    elif port in self.udp_portsrc:
                        proto_src.append(17)

            # Printing the Attackers' information:
            for ip in attacker_address:
                LOG.info('\033[93m** Attacker IP: %s **\033[0m', ip)
            for port in attacker_port:
                LOG.info('\033[93m** Attacker Portsrc: %s **\033[0m', port)

            # Don't store the last entropy values because it was during an abnormal traffic 
            del self.entropy_ipsrc[-1]
            del self.entropy_ipdst[-1]
            if (attack_type != 3 and attack_type != 4):
                del self.entropy_portsrc[-1]
                del self.entropy_portdst[-1]

            # Mitigation process
            # Mitigation only if there is all the information needed:
            if (len(attacker_address) != 0 and len(victim_address) != 0 and len(attacker_port) != 0 and len(
                    victim_port) != 0):
                for dp in self.datapaths.values():
                    # ICMP Mitigation
                    if (attack_type == 3 or attack_type == 4):
                        i = 0
                        if (len(attacker_address) != 0):
                            mitigation_type = 2
                            while (i < len(attacker_address)):
                                self.mitigation(dp, mitigation_type, attacker_address[i], 1, None)
                                i += 1
                        elif (len(victim_address) != 0):
                            while (i < len(victim_address)):
                                self.mitigation(dp, mitigation_type, victim_address[i], 1, None)
                                i += 1
                    else:
                        if (len(attacker_address) != 0):
                            mitigation_type = 2
                            i = j = 0
                            while i < len(attacker_address):
                                if len(attacker_port) != 0:
                                    for j in range(len(attacker_port)):
                                        self.mitigation(dp, mitigation_type, attacker_address[i], proto_src[j],
                                                        attacker_port[j])
                                else:
                                    self.mitigation(dp, mitigation_type, attacker_address[i], None, None)
                                i += 1
                        elif (len(victim_address) != 0):
                            i = j = 0
                            while i < len(victim_address):
                                if len(victim_port) != 0:
                                    for j in range(len(victim_port)):
                                        self.mitigation(dp, mitigation_type, victim_address[i], proto_dst[j],
                                                        victim_port[j])
                                else:
                                    self.mitigation(dp, mitigation_type, victim_address[i], None, None)
                                i += 1

    def mitigation(self, datapath, mitigation_type, ip_address, protocol_type, port):
        if (mitigation_type == 1):  # Mitigation of the Victim's traffic
            if (port != None):
                if (protocol_type == 6):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip_address,
                                              ip_proto=protocol_type, tcp_dst=port)
                elif (protocol_type == 17):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip_address,
                                              ip_proto=protocol_type, udp_dst=port)
                elif (protocol_type == 0):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip_address,
                                              ip_proto=in_proto.IPPROTO_TCP, tcp_dst=port)
                    actions = []
                    self.add_flow(datapath=datapath, table_id=0, priority=100,
                                  match=match, actions=actions)
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip_address,
                                              ip_proto=in_proto.IPPROTO_UDP, udp_dst=port)
            else:
                if (protocol_type == 1):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip_address,
                                              ip_proto=protocol_type)
                else:
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip_address)

            actions = []
            self.add_flow(datapath=datapath, table_id=0, priority=100,
                          match=match, actions=actions)
            LOG.info('\033[94m** Mitigation (of the Victim) message sent **\033[0m')
        elif (mitigation_type == 2):  # Mitigation of the Attacker's traffic
            if (port != None):
                if (protocol_type == 6):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_address,
                                              ip_proto=protocol_type, tcp_src=port)
                elif (protocol_type == 17):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_address,
                                              ip_proto=protocol_type, udp_src=port)
                elif (protocol_type == 0):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_address,
                                              ip_proto=in_proto.IPPROTO_TCP, tcp_src=port)
                    actions = []
                    self.add_flow(datapath=datapath, table_id=0, priority=100,
                                  match=match, actions=actions)
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_address,
                                              ip_proto=in_proto.IPPROTO_UDP, udp_src=port)
            else:
                if (protocol_type == 1):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_address,
                                              ip_proto=protocol_type)
                else:
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_address)

            actions = []
            self.add_flow(datapath=datapath, table_id=0, priority=100,
                          match=match, actions=actions)
            LOG.info('\033[94m** Mitigation (of the Attacker) message sent **\033[0m')

    def _request_stats(self, datapath):
        for table in range(6):
            req = bebaparser.OFPExpStateStatsMultipartRequestAndDelete(datapath, table_id=table)
            datapath.send_msg(req)

    def convertPort2Int(self, keys):
        port_int = 0
        for index in range(len(keys)):
            port_int += keys[index] * math.pow(256, index)
        return int(port_int)

    def storeInFile(self):
        # Storing the time
        self.abscisse_time.append(timewindow * self.timer)
        self.timer += 1

        with open('entropy.csv', 'ab') as csvfile:
            writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(
                [self.abscisse_time[-1], self.entropy_ipsrc[-1], self.entropy_ipdst[-1], self.entropy_portsrc[-1],
                 self.entropy_portdst[-1]])
            csvfile.close()

        with open('counters.csv', 'ab') as csvfile:
            writer = csv.writer(csvfile, delimiter=';', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            for index in self.ipsrc:
                writer.writerow([self.abscisse_time[-1], index, self.ipsrc[index], None, None, None, None, None, None])
            for index in self.ipdst:
                writer.writerow([self.abscisse_time[-1], None, None, index, self.ipdst[index], None, None, None, None])
            for index in self.portsrc:
                writer.writerow(
                    [self.abscisse_time[-1], None, None, None, None, index, self.portsrc[index], None, None])
            for index in self.portdst:
                writer.writerow(
                    [self.abscisse_time[-1], None, None, None, None, None, None, index, self.portdst[index]])
            csvfile.close()

        with open('counter_ip_src.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile, delimiter=';', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(["IP Src", " IP Src ID", " State"])
            position_id = 1
            for index in self.ipsrc:
                writer.writerow([index, position_id, self.ipsrc[index]])
                position_id += 1
            csvfile.close()

        with open('counter_ip_dst.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile, delimiter=';', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(["IP Dst", " IP Dst ID", " State"])
            position_id = 1
            for index in self.ipdst:
                writer.writerow([index, position_id, self.ipdst[index]])
                position_id += 1
            csvfile.close()

        with open('counter_port_src.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(["Port Src", " State"])
            for index in self.portsrc:
                writer.writerow([index, self.portsrc[index]])
            csvfile.close()

        with open('counter_port_dst.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(["Port Dst", " State"])
            for index in self.portdst:
                writer.writerow([index, self.portdst[index]])
            csvfile.close()

    def printcounters(self):
        # Print the state stats of the dictionaries
        if ((len(self.ipsrc) != 0) and (len(self.ipdst) != 0) and (len(self.portsrc) != 0) and (
            len(self.portdst) != 0)):
            LOG.info('===========================================')
            for index in self.ipsrc:
                LOG.info('IPsrc= %s \t\tState= %s', index, self.ipsrc[index])
            LOG.info(' ')
            for index in self.ipdst:
                LOG.info('IPdst= %s \t\tState= %s', index, self.ipdst[index])
            LOG.info(' ')
            for index in self.portsrc:
                LOG.info('Portsrc= %d \t\t\tState= %s', index, self.portsrc[index])
            LOG.info(' ')
            for index in self.portdst:
                LOG.info('Portdst= %d \t\t\tState= %s', index, self.portdst[index])
        # State Stats General Parser:
        """ LOG.info('Length=%s Table ID=%s Duration_sec=%s Duration_nsec=%s Field_count=%s\n'
            'Keys:%s State=%s\n'
            'Hard_rollback=%s Idle_rollback=%s Hard_timeout=%s Idle_timeout=%s',
            str(state_stats_list[index].length), str(state_stats_list[index].table_id), str(state_stats_list[index].dur_sec), str(state_stats_list[index].dur_nsec), str(state_stats_list[index].field_count),
            bebaparser.state_entry_key_to_str(state_stats_list[index].fields, state_stats_list[index].entry.key, state_stats_list[index].entry.key_count), str(state_stats_list[index].entry.state),
            str(state_stats_list[index].hard_rb), str(state_stats_list[index].idle_rb), str(state_stats_list[index].hard_to), str(state_stats_list[index].idle_to))
            LOG.info('*************************************************************') """

    def entropy_computation(self):
        # Port src dictionary = TCP + UDP Port src dictionaries
        for index in self.udp_portsrc:
            if index in self.portsrc:  # We add the two values
                new_port = self.portsrc[index] + self.udp_portsrc[index]
                self.portsrc[index] = new_port
            else:  # We create a new entry
                self.portsrc[index] = self.udp_portsrc[index]
        # Port dst dictionary = TCP + UDP Port dst dictionaries
        for index in self.udp_portdst:
            if index in self.portdst:
                new_port = self.portdst[index] + self.udp_portdst[index]
                self.portdst[index] = new_port
            else:
                self.portdst[index] = self.udp_portdst[index]

        # Printing the counters:
        self.printcounters()

        # Entropy calculation:
        entropy_ip_src = self.entropy(self.ipsrc)
        entropy_ip_dst = self.entropy(self.ipdst)
        entropy_port_src = self.entropy(self.portsrc)
        entropy_port_dst = self.entropy(self.portdst)

        # Storing entropies in lists:
        self.entropy_ipsrc.append(entropy_ip_src)
        self.entropy_ipdst.append(entropy_ip_dst)
        self.entropy_portsrc.append(entropy_port_src)
        self.entropy_portdst.append(entropy_port_dst)

        # Storing the Counters + Entropies in an output file:
        self.storeInFile()

        # Printing the entropies:
        # LOG.info('===========================================')
        # LOG.info('Entropy IP Src')
        # LOG.info(self.entropy_ipsrc)
        # LOG.info('Entropy IP Dst')
        # LOG.info(self.entropy_ipdst)
        # LOG.info('Entropy Port Src')
        # LOG.info(self.entropy_portsrc)
        # LOG.info('Entropy Port Dst')
        # LOG.info(self.entropy_portdst)

        # Detection process
        if ((len(self.entropy_ipsrc) > int(20 / timewindow)) and sum(
                self.entropy_ipsrc) > 1):  # Wait 20s before starting the detection, we need at least 2 elements in entropy lists
            self.detection()

        # Emptying dictionaries
        self.ipsrc.clear()
        self.ipdst.clear()
        self.portsrc.clear()
        self.portdst.clear()
        self.tcp_portsrc.clear()
        self.tcp_portdst.clear()
        self.udp_portsrc.clear()
        self.udp_portdst.clear()

    @set_ev_cls(ofp_event.EventOFPExperimenterStatsReply, MAIN_DISPATCHER)
    def _state_stats_reply_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        # Retreive and store states stats information 
        if (msg.body.experimenter == 0XBEBABEBA):
            if (msg.body.exp_type == bebaproto.OFPMP_EXP_STATE_STATS_AND_DELETE):
                data = msg.body.data
                state_stats_list = bebaparser.OFPStateStats.parser(msg, 0)
                if (state_stats_list != 0):
                    self.replies += 1
                    for index in range(len(state_stats_list)):
                        if (state_stats_list[index].entry.state != 0):

                            if (int(state_stats_list[index].table_id) == 0):  # IP src dictionary
                                self.ipsrc[(str(state_stats_list[index].entry.key)[1:-1]).replace(", ", ".")] = \
                                state_stats_list[index].entry.state

                            elif (int(state_stats_list[index].table_id) == 1):  # IP dst dictionary
                                self.ipdst[(str(state_stats_list[index].entry.key)[1:-1]).replace(", ", ".")] = \
                                state_stats_list[index].entry.state

                            elif (int(state_stats_list[index].table_id) == 2):  # TCP Port src + Port src dictionaries
                                portsrc = self.convertPort2Int(state_stats_list[index].entry.key)
                                self.portsrc[portsrc] = state_stats_list[index].entry.state
                                self.tcp_portsrc[portsrc] = state_stats_list[index].entry.state

                            elif (int(state_stats_list[index].table_id) == 3):  # TCP Port dst + Port dst dictionaries
                                portdst = self.convertPort2Int(state_stats_list[index].entry.key)
                                self.portdst[portdst] = state_stats_list[index].entry.state
                                self.tcp_portdst[portdst] = state_stats_list[index].entry.state

                            elif (int(state_stats_list[index].table_id) == 4):  # UDP Port src dictionary
                                portsrc = self.convertPort2Int(state_stats_list[index].entry.key)
                                self.udp_portsrc[portsrc] = state_stats_list[index].entry.state

                            elif (int(state_stats_list[index].table_id) == 5):  # UDP Port dst dictionary
                                portdst = self.convertPort2Int(state_stats_list[index].entry.key)
                                self.udp_portdst[portdst] = state_stats_list[index].entry.state
                else:
                    LOG.info("No data")
        if (self.replies == 6):  # If we have all the replies
            if (len(self.ipsrc) != 0):  # if counters are != 0
                self.entropy_computation()
