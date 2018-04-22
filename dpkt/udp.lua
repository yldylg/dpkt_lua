local meta = require("dpkt.meta")
local utils = require("dpkt.utils")
local UDP = {}
setmetatable(UDP, meta)

function UDP:init(buf)
    local o = {__buf = buf}
    setmetatable(o, {__index = self, __name = 'UDP'})
    o:unpack()
    return o
end

function UDP:unpack()
    local sport, dport, len, sum = string.unpack('I2I2I2I2', self.__buf)
    self.sport = utils.ntohs(sport)
    self.dport = utils.ntohs(dport)
    self.len = utils.ntohs(len)
    self.sum = utils.ntohs(sum)
    self.data = string.sub(self.__buf, 9)
end

function UDP:pack()
end

return UDP
