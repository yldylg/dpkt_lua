local meta = require("dpkt.meta")
local utils = require("dpkt.utils")
local Dot11 = {
    -- Frame Types
    MGMT_TYPE = 0,
    CTL_TYPE = 1,
    DATA_TYPE = 2,
    -- Frame Sub-Types
    M_ASSOC_REQ = 0,
    M_ASSOC_RESP = 1,
    M_REASSOC_REQ = 2,
    M_REASSOC_RESP = 3,
    M_PROBE_REQ = 4,
    M_PROBE_RESP = 5,
    M_BEACON = 8,
    M_ATIM = 9,
    M_DISASSOC = 10,
    M_AUTH = 11,
    M_DEAUTH = 12,
    M_ACTION = 13,
    C_BLOCK_ACK_REQ = 8,
    C_BLOCK_ACK = 9,
    C_PS_POLL = 10,
    C_RTS = 11,
    C_CTS = 12,
    C_ACK = 13,
    C_CF_END = 14,
    C_CF_END_ACK = 15,
    D_DATA = 0,
    D_DATA_CF_ACK = 1,
    D_DATA_CF_POLL = 2,
    D_DATA_CF_ACK_POLL = 3,
    D_NULL = 4,
    D_CF_ACK = 5,
    D_CF_POLL = 6,
    D_CF_ACK_POLL = 7,
    D_QOS_DATA = 8,
    D_QOS_CF_ACK = 9,
    D_QOS_CF_POLL = 10,
    D_QOS_CF_ACK_POLL = 11,
    D_QOS_NULL = 12,
    D_QOS_CF_POLL_EMPTY = 14,
    -- DS Flags
    DATA_DATA = 0,
    TO_DS_FLAG = 10,
    FROM_DS_FLAG = 1,
    INTER_DS_FLAG = 11,
    -- Bitshifts for Frame Control
    _VERSION_MASK = 0x0300,
    _TYPE_MASK = 0x0c00,
    _SUBTYPE_MASK = 0xf000,
    _TO_DS_MASK = 0x0001,
    _FROM_DS_MASK = 0x0002,
    _MORE_FRAG_MASK = 0x0004,
    _RETRY_MASK = 0x0008,
    _PWR_MGT_MASK = 0x0010,
    _MORE_DATA_MASK = 0x0020,
    _WEP_MASK = 0x0040,
    _ORDER_MASK = 0x0080,
    _VERSION_SHIFT = 8,
    _TYPE_SHIFT = 10,
    _SUBTYPE_SHIFT = 12,
    _TO_DS_SHIFT = 0,
    _FROM_DS_SHIFT = 1,
    _MORE_FRAG_SHIFT = 2,
    _RETRY_SHIFT = 3,
    _PWR_MGT_SHIFT = 4,
    _MORE_DATA_SHIFT = 5,
    _WEP_SHIFT = 6,
    _ORDER_SHIFT = 7,
    -- IEs
    IE_SSID = 0,
    IE_RATES = 1,
    IE_FH = 2,
    IE_DS = 3,
    IE_CF = 4,
    IE_TIM = 5,
    IE_IBSS = 6,
    IE_HT_CAPA = 45,
    IE_ESR = 50,
    IE_HT_INFO = 61,
    FCS_LENGTH = 4,
    -- Block Ack control constants
    _ACK_POLICY_SHIFT = 0,
    _MULTI_TID_SHIFT = 1,
    _COMPRESSED_SHIFT = 2,
    _TID_SHIFT = 12,
    _ACK_POLICY_MASK = 0x0001,
    _MULTI_TID_MASK = 0x0002,
    _COMPRESSED_MASK = 0x0004,
    _TID_MASK = 0xf000,
    _COMPRESSED_BMP_LENGTH = 8,
    _BMP_LENGTH = 128,
    -- Action frame categories
    BLOCK_ACK = 3,
    -- Block ack category action codes
    BLOCK_ACK_CODE_REQUEST = 0,
    BLOCK_ACK_CODE_RESPONSE = 1
}
setmetatable(Dot11, meta)

local msub, csub, dsub = {}, {}, {}
--
msub[Dot11.M_BEACON] = function(self, data)
    local timestamp, interval, capability = string.unpack('I8I2I2', data)
    self.timestamp = timestamp
    self.interval = utils.ntohs(interval)
    self.capability = capability
    return string.sub(data, 13)
end
msub[Dot11.M_ASSOC_REQ] = function(self, data)
    local capability, interval = string.unpack('I2I2', data)
    self.capability = capability
    self.interval = utils.ntohs(interval)
    return string.sub(data, 5)
end
msub[Dot11.M_ASSOC_RESP] = function(self, data)
    local capability, status, aid = string.unpack('I2I2I2', data)
    self.capability = capability
    self.status = status
    self.aid = aid
    return string.sub(data, 7)
end
msub[Dot11.M_DISASSOC] = function(self, data)
    local reason = string.unpack('I2', data)
    self.reason = reason
    return string.sub(data, 3)
end
msub[Dot11.M_REASSOC_REQ] = function(self, data)
    local capability, interval, current_ap = string.unpack('I2I2I6', data)
    self.capability = capability
    self.interval = utils.ntohs(interval)
    self.current_ap = utils.mac2str(current_ap)
    return string.sub(data, 11)
end
msub[Dot11.M_REASSOC_RESP] = msub[Dot11.M_ASSOC_RESP]
msub[Dot11.M_AUTH] = function(self, data)
    local algorithm, auth_seq = string.unpack('I2I2', data)
    self.algorithm = algorithm
    self.auth_seq = auth_seq
    return string.sub(data, 5)
end
msub[Dot11.M_PROBE_REQ] = function(self, data)
    return data
end
msub[Dot11.M_ATIM] = msub[Dot11.M_PROBE_REQ]
msub[Dot11.M_PROBE_RESP] = msub[Dot11.M_BEACON]
msub[Dot11.M_DEAUTH] = msub[Dot11.M_DISASSOC]
msub[Dot11.M_ACTION] = function(self, data)
    local category, code = string.unpack('I1I1', data)
    self.category = category
    self.code = code
    return string.sub(data, 3)
end
--
csub[Dot11.C_RTS] = function(self, data)
    --
end
csub[Dot11.C_CTS] = function(self, data)
    --
end
csub[Dot11.C_ACK] = function(self, data)
    --
end
csub[Dot11.C_BLOCK_ACK_REQ] = function(self, data)
    --
end
csub[Dot11.C_BLOCK_ACK] = function(self, data)
    --
end
csub[Dot11.C_CF_END] = function(self, data)
    --
end
--
dsub[Dot11.DATA_DATA] = function(self, data)
    --
end
dsub[Dot11.FROM_DS_FLAG] = function(self, data)
    --
end
dsub[Dot11.TO_DS_FLAG] = function(self, data)
    --
end
dsub[Dot11.INTER_DS_FLAG] = function(self, data)
    --
end
--

Dot11.frame_parser = {}
Dot11.frame_parser[Dot11.MGMT_TYPE] = {function(self, data)
    local dst, src, bssid, frag_seq = string.unpack('I6I6I6I2', data)
    self.src = utils.mac2str(src)
    self.dst = utils.mac2str(dst)
    self.bssid = utils.mac2str(bssid)
    self.frag_seq = frag_seq
    return string.sub(data, 21)
end, msub}
Dot11.frame_parser[Dot11.CTL_TYPE] = {function(self, data)
    return data
end, csub}
Dot11.frame_parser[Dot11.DATA_TYPE] = {function(self, data)
    --
end, dsub}
--

function Dot11.unpack_ie(data)
    local id, len = string.unpack('I1I1', data)
    return {id=id, len=len, info=string.sub(data, 3, 2 + len)}
end
--
function Dot11.unpack_fh(data)
    local id, len, tu, hopset, hoppattern, hopindex = string.unpack('I1I1I2I1I1I1', data)
    return {id=id, len=len, tu=tu, hopset=hopset, hoppattern=hoppattern, hopindex=hopindex}
end
--
function Dot11.unpack_ds(data)
    local id, len, ch = string.unpack('I1I1I1', data)
    return {id=id, len=len, ch=ch}
end
--
function Dot11.unpack_cf(data)
    local id, len, count, period, max, dur = string.unpack('I1I1I1I1I2I2', data)
    return {id=id, len=len, count=count, period=period, max=max, dur=dur}
end
--
function Dot11.unpack_tim(data)
    local id, len, count, period, ctrl = string.unpack('I1I1I1I1I2', data)
    return {id=id, len=len, count=count, period=period, ctrl=ctrl, bitmap=string.sub(data, 6, 2 + len)}
end
--
function Dot11.unpack_ibss(data)
    local id, len, atim = string.unpack('I1I1I2', data)
    return {id=id, len=len, atim=atim}
end

Dot11.ie_decoder = {}
Dot11.ie_decoder[Dot11.IE_SSID] = {'ssid', Dot11.unpack_ie}
Dot11.ie_decoder[Dot11.IE_RATES] = {'rate', Dot11.unpack_ie}
Dot11.ie_decoder[Dot11.IE_FH] = {'fh', Dot11.unpack_fh}
Dot11.ie_decoder[Dot11.IE_DS] = {'ds', Dot11.unpack_ds}
Dot11.ie_decoder[Dot11.IE_CF] = {'cf', Dot11.unpack_cf}
Dot11.ie_decoder[Dot11.IE_TIM] = {'tim', Dot11.unpack_tim}
Dot11.ie_decoder[Dot11.IE_IBSS] = {'ibss', Dot11.unpack_ibss}
Dot11.ie_decoder[Dot11.IE_HT_CAPA] = {'ht_capa', Dot11.unpack_ie}
Dot11.ie_decoder[Dot11.IE_ESR] = {'esr', Dot11.unpack_ie}
Dot11.ie_decoder[Dot11.IE_HT_INFO] = {'ht_info', Dot11.unpack_ie}
--

function Dot11:init(buf)
    local o = {__buf = buf}
    setmetatable(o, {__index = self, __name = 'Dot11'})
    o:unpack()
    return o
end

function Dot11:unpack()
    local framectl, duration = string.unpack('I2I2', self.__buf)
    self.framectl = utils.ntohs(framectl)
    self.duration = utils.ntohs(duration)
    -- self.data = string.sub(self.__buf, 9)
    self.version = (self.framectl & self._VERSION_MASK) >> self._VERSION_SHIFT
    self.type = (self.framectl & self._TYPE_MASK) >> self._TYPE_SHIFT
    self.subtype = (self.framectl & self._SUBTYPE_MASK) >> self._SUBTYPE_SHIFT
    self.to_ds = (self.framectl & self._TO_DS_MASK) >> self._TO_DS_SHIFT
    self.from_ds = (self.framectl & self._FROM_DS_MASK) >> self._FROM_DS_SHIFT
    self.more_frag = (self.framectl & self._MORE_FRAG_MASK) >> self._MORE_FRAG_SHIFT
    self.retry = (self.framectl & self._RETRY_MASK) >> self._RETRY_SHIFT
    self.pwr_mgt = (self.framectl & self._PWR_MGT_MASK) >> self._PWR_MGT_SHIFT
    self.more_data = (self.framectl & self._MORE_DATA_MASK) >> self._MORE_DATA_SHIFT
    self.wep = (self.framectl & self._WEP_MASK) >> self._WEP_SHIFT
    self.order = (self.framectl & self._ORDER_MASK) >> self._ORDER_SHIFT
    --
    local data = string.sub(self.__buf, 5)
    local parser = Dot11.frame_parser[self.type]
    data = parser[1](self, data)
    data = parser[2][self.subtype](self, data)
    if self.type == Dot11.MGMT_TYPE then
        self:unpack_ies(data)
    end
    -- print(self.src, self.dst, self.bssid, self.ssid.info)
end

function Dot11:unpack_ies(data)
    while #data > Dot11.FCS_LENGTH do
        local ie_id = string.unpack('I1', data)
        local tmp = Dot11.ie_decoder[ie_id]
        local name, decoder
        if tmp ~= nil then
            name = tmp[1]
            decoder = tmp[2]
        else
            name = 'ie_' .. ie_id
            decoder = Dot11.unpack_ie
        end
        local result = decoder(data)
        self[name] = result
        data = string.sub(data, 3 + result.len)
        -- print(result, #data, result.id, result.len)
    end
end

function Dot11:pack()
end

return Dot11
