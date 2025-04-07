from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_4
from os_ken.lib.packet import packet
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import in_proto
from os_ken.lib.packet import arp
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import tcp
from os_ken.lib.packet.tcp import TCP_SYN
from os_ken.lib.packet.tcp import TCP_FIN
from os_ken.lib.packet.tcp import TCP_RST
from os_ken.lib.packet.tcp import TCP_ACK
from os_ken.lib.packet.ether_types import ETH_TYPE_IP, ETH_TYPE_ARP
import datetime

class Nat(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Nat, self).__init__(*args, **kwargs)
        self.lmac = '00:00:00:00:00:10'
        self.emac = '00:00:00:00:00:20'
        self.hostmacs = {
                '10.0.1.100': '00:00:00:00:00:01',
                '10.0.2.100': '00:00:00:00:00:02',
                '10.0.2.101': '00:00:00:00:00:03',
                }

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        return out

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        dp = ev.msg.datapath
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        acts = [psr.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, psr.OFPMatch(), acts)

    def add_flow(self, dp, prio, match, acts, buffer_id=None, delete=False):
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        bid = buffer_id if buffer_id is not None else ofp.OFP_NO_BUFFER
        if delete:
            mod = psr.OFPFlowMod(datapath=dp, command=dp.ofproto.OFPFC_DELETE,
                    out_port=dp.ofproto.OFPP_ANY, out_group=dp.ofproto.OFPG_ANY,
                    match=match)
        else:
            ins = [psr.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, acts)]
            mod = psr.OFPFlowMod(datapath=dp, buffer_id=bid, priority=prio,
                                match=match, instructions=ins)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        in_port, pkt = (msg.match['in_port'], packet.Packet(msg.data))
        dp = msg.datapath
        ofp, psr, did = (dp.ofproto, dp.ofproto_parser, format(dp.id, '016d'))
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ETH_TYPE_ARP:
            ah = pkt.get_protocols(arp.arp)[0]
            if ah.opcode == arp.ARP_REQUEST:
                print('ARP', pkt)
                ar = packet.Packet()
                ar.add_protocol(ethernet.ethernet(ethertype=eth.ethertype,
                    dst=eth.src,
                    src=self.emac if in_port == 1 else self.lmac))
                ar.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                    src_mac=self.emac if in_port == 1 else self.lmac,
                    dst_mac=ah.src_mac, src_ip=ah.dst_ip, dst_ip=ah.src_ip))
                out = self._send_packet(dp, in_port, ar)
                print('ARP Rep', ar)
                dp.send_msg(out)
            return

        acts = [psr.OFPActionOutput(ofp.OFPPC_NO_FWD)]

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = psr.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                               in_port=in_port, actions=acts, data=data)
        dp.send_msg(out)
