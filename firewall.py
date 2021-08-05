# tele4642 mini project

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.k = int(input('set hosts number: '))
        self.mac_to_port = {}
        self.src_mac = []       # list of src
        self.dst_mac = []       # list of dst
        self.count_dst = []     # count of access
        self.count_src = []
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self.monitor)
        self.linklimit = 5
        self.dstlimit = 2

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, idle_timeout=0)      # table-miss flow entry

        #judge datapath's status to decide how to operate
        if datapath.id not in self.datapaths:
            self.datapaths[datapath.id] = datapath
            self.logger.debug("Regist datapath: %16x",datapath.id)

    def add_flow(self, datapath, priority, match, actions, idle_timeout, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, idle_timeout=idle_timeout, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, idle_timeout=idle_timeout, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']      # get the received port number from packet_in message.

        pkt = packet.Packet(msg.data)       # Get the packet and parses it

        eth = pkt.get_protocol(ethernet.ethernet)       # ethernet

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)       # get Datapath ID to identify OpenFlow switches.
        self.mac_to_port.setdefault(dpid, {})
        if int(dst[:1]) != 3:
            self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # if the destination mac address is already learned,
        # decide which port to output the packet, otherwise FLOOD.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        self.count(src, dst)
        actions = [parser.OFPActionOutput(out_port)]        # construct action list.
        
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, 0, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions, 0)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        # construct packet_out message and send it.
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def monitor(self):
        '''
        design a monitor on timing system to request switch infomations about flow
        '''
        while True:    #initiatie to request port and flow info all the time
            for dp in self.datapaths.values():
                self.send_flow_stats_request(dp)
            hub.sleep(10)    #pause to sleep to wait reply, and gave time to other gevent to request

    def send_flow_stats_request(self, dp):
        parser = dp.ofproto_parser
        req = parser.OFPFlowStatsRequest(dp)
        dp.send_msg(req)
    
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        for stat in ev.msg.body:
            if stat.priority == 1:
                if stat.packet_count > 0:
                    if len(self.dst_mac) > 0:
                        for i in range(len(self.dst_mac)):
                            if stat.match['eth_dst'] == self.dst_mac[i]:
                                self.count_dst[i] += 1
                    if (stat.packet_count >= self.linklimit and stat.byte_count/stat.packet_count < 100):
                        self.add_flow(datapath=datapath, priority=10, match=stat.match, actions=[], idle_timeout=10)
                        print('drop link:')
                        print(stat.match['eth_src'],stat.match['eth_dst'])
                    mod = parser.OFPFlowMod(datapath=datapath, priority=stat.priority, 
                                            idle_timeout=stat.idle_timeout, match=stat.match, 
                                            instructions=stat.instructions, flags=ofproto.OFPFF_RESET_COUNTS) # reset counts
                    datapath.send_msg(mod)
        if len(self.dst_mac) > 0:
            for i in range(len(self.count_dst)):
                if self.count_dst[i] >= self.dstlimit:
                    match = parser.OFPMatch(eth_dst=self.dst_mac[i])
                    self.add_flow(datapath=datapath, priority=11, match=match, actions=[], idle_timeout=10)
                    print('drop dst_mac:')
                    print(self.dst_mac[i])
            self.count_dst = [i * 0 for i in self.count_dst]        # reset
    
    def count(self, src, dst):      
        if len(self.dst_mac) == 0:          # dst mac address
            self.dst_mac.append(dst)
            self.count_dst.append(0)
        else:
            for i in range(len(self.dst_mac)):
                if dst == self.dst_mac[i]:
                    break
                if i == len(self.dst_mac) - 1:
                    self.dst_mac.append(dst)
                    self.count_dst.append(0)