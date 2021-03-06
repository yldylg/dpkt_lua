local meta = require("dpkt.meta")
local utils = require("dpkt.utils")
local Ethernet = {
    ETH_TYPE_PUP = 0x0200,  -- PUP protocol
    ETH_TYPE_IP = 0x0800,  -- IP protocol
    ETH_TYPE_ARP = 0x0806,  -- address resolution protocol
    ETH_TYPE_AOE = 0x88a2,  -- AoE protocol
    ETH_TYPE_CDP = 0x2000,  -- Cisco Discovery Protocol
    ETH_TYPE_DTP = 0x2004,  -- Cisco Dynamic Trunking Protocol
    ETH_TYPE_REVARP = 0x8035,  -- reverse addr resolution protocol
    ETH_TYPE_8021Q = 0x8100,  -- IEEE 802.1Q VLAN tagging
    ETH_TYPE_IPX = 0x8137,  -- Internetwork Packet Exchange
    ETH_TYPE_IP6 = 0x86DD,  -- IPv6 protocol
    ETH_TYPE_PPP = 0x880B,  -- PPP
    ETH_TYPE_MPLS = 0x8847,  -- MPLS
    ETH_TYPE_MPLS_MCAST = 0x8848,  -- MPLS Multicast
    ETH_TYPE_PPPoE_DISC = 0x8863,  -- PPP Over Ethernet Discovery Stage
    ETH_TYPE_PPPoE = 0x8864,  -- PPP Over Ethernet Session Stage
    ETH_TYPE_LLDP = 0x88CC,  -- Link Layer Discovery Protocol
    ETH_TYPE_TEB = 0x6558,  -- Transparent Ethernet Bridging
}
setmetatable(Ethernet, meta)

function Ethernet:init(buf)
    local o = {__buf = buf}
    setmetatable(o, {__index = self, __name = 'Ethernet'})
    o:unpack()
    return o
end

function Ethernet:unpack()
    local dst, src, subtype = string.unpack('I6I6I2', self.__buf)
    self.src = utils.mac2str(src)
    self.dst = utils.mac2str(dst)
    self.subtype = utils.ntohs(subtype)
    self.data = string.sub(self.__buf, 15)
end

function Ethernet:pack()
end

return Ethernet
