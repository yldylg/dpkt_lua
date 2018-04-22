local meta = require("dpkt.meta")
local utils = require("dpkt.utils")
local TCP = {
    TH_FIN = 0x01,  -- end of data
    TH_SYN = 0x02,  -- synchronize sequence numbers
    TH_RST = 0x04,  -- reset connection
    TH_PUSH = 0x08,  -- push
    TH_ACK = 0x10,  -- acknowledgment number set
    TH_URG = 0x20,  -- urgent pointer set
    TH_ECE = 0x40,  -- ECN echo, RFC 3168
    TH_CWR = 0x80,  -- congestion window reduced
    TCP_PORT_MAX = 65535,  -- maximum port
    TCP_WIN_MAX = 65535  -- maximum (unscaled) window
}
setmetatable(TCP, meta)

function TCP:init(buf)
    local o = {__buf = buf}
    setmetatable(o, {__index = self, __name = 'TCP'})
    o:unpack()
    return o
end

function TCP:unpack()
    local sport, dport, seq, ack, _hl_fg, win, sum, urp = string.unpack('I2I2I4I4I2I2I2I2', self.__buf)
    self.sport = utils.ntohs(sport)
    self.dport = utils.ntohs(dport)
    self.seq = utils.ntohl(seq)
    self.ack = utils.ntohl(ack)
    self.hdrlen = (_hl_fg >> 4) & 0x0f
    self.flags = (_hl_fg >> 8) & 0x3f
    self.win = utils.ntohs(win)
    self.sum = utils.ntohs(sum)
    self.urp = urp
    self.data = string.sub(self.__buf, self.hdrlen * 4 + 1)
end

function TCP:pack()
end

return TCP
