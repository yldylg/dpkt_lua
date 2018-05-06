local meta = require("dpkt.meta")
local utils = require("dpkt.utils")
local EAPOL = {}
setmetatable(EAPOL, meta)

function EAPOL:init(buf)
    local o = {__buf = buf}
    setmetatable(o, {__index = self, __name = 'EAPOL'})
    o:unpack()
    return o
end

function EAPOL:unpack()
    local version, type, len = string.unpack('I1I1I2', self.__buf)
    self.version = version
    self.type = type
    self.len = utils.ntohs(len)
    self.data = string.sub(self.__buf, 5)
end

function EAPOL:pack()
end

return EAPOL
