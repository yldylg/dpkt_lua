local meta = require("dpkt.meta")
local utils = require("dpkt.utils")
local LLC = {}
setmetatable(LLC, meta)

function LLC:init(buf)
    local o = {__buf = buf}
    setmetatable(o, {__index = self, __name = 'LLC'})
    o:unpack()
    return o
end

function LLC:unpack()
    local dsap, ssap, ctl = string.unpack('I1I1I1', self.__buf)
    self.dsap = dsap
    self.ssap = ssap
    self.ctl = ctl
    local data = string.sub(self.__buf, 4)
    --
    if self.dsap == 0xaa and self.ssap == 0xaa then
        local oui, type = string.unpack('I3I2', data)
        self.oui = utils.ntohls(oui)
        self.type = utils.ntohs(type)
        data = string.sub(data, 6)
    end
    self.data = data
end

function LLC:pack()
end

return LLC
