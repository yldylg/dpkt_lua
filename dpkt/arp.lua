local meta = require("dpkt.meta")
local utils = require("dpkt.utils")
local ARP = {
    -- Hardware address format
    ARP_HRD_ETH = 0x0001,  -- ethernet hardware
    ARP_HRD_IEEE802 = 0x0006,  -- IEEE 802 hardware
    -- Protocol address format
    ARP_PRO_IP = 0x0800,  -- IP protocol
    -- ARP operation
    ARP_OP_REQUEST = 1,  -- request to resolve ha given pa
    ARP_OP_REPLY = 2,  -- response giving hardware address
    ARP_OP_REVREQUEST = 3,  -- request to resolve pa given ha
    ARP_OP_REVREPLY = 4  -- response giving protocol address
}
setmetatable(ARP, meta)

function ARP:init(buf)
    local o = {__buf = buf}
    setmetatable(o, {__index = self, __name = 'ARP'})
    o:unpack()
    return o
end

function ARP:unpack()
    local hrd, pro, hln, pln, op, sha, spa, tha, tpa = string.unpack('I2I2I1I1I2I6I4I6I4', self.__buf)
    self.hrd = utils.ntohs(hrd)
    self.pro = utils.ntohs(pro)
    self.hln = hln
    self.pln = pln
    self.op = utils.ntohs(op)
    self.sha = utils.mac2str(sha)
    self.spa = utils.ip2str(spa)
    self.tha = utils.mac2str(tha)
    self.tpa = utils.ip2str(tpa)
    self.data = string.sub(self.__buf, 29)
    print(self.hrd, self.pro, self.hln, self.pln, self.op, self.sha, self.spa, self.tha, self.tpa)
end

function ARP:pack()
end

return ARP
