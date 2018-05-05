local meta = require("dpkt.meta")
local utils = require("dpkt.utils")
local Radiotap = {
    -- Present flags
    _TSFT_MASK = 0x1000000,
    _FLAGS_MASK = 0x2000000,
    _RATE_MASK = 0x4000000,
    _CHANNEL_MASK = 0x8000000,
    _FHSS_MASK = 0x10000000,
    _ANT_SIG_MASK = 0x20000000,
    _ANT_NOISE_MASK = 0x40000000,
    _LOCK_QUAL_MASK = 0x80000000,
    _TX_ATTN_MASK = 0x10000,
    _DB_TX_ATTN_MASK = 0x20000,
    _DBM_TX_POWER_MASK = 0x40000,
    _ANTENNA_MASK = 0x80000,
    _DB_ANT_SIG_MASK = 0x100000,
    _DB_ANT_NOISE_MASK = 0x200000,
    _RX_FLAGS_MASK = 0x400000,
    _CHANNELPLUS_MASK = 0x200,
    _EXT_MASK = 0x1,
    -- Present shifts
    _TSFT_SHIFT = 24,
    _FLAGS_SHIFT = 25,
    _RATE_SHIFT = 26,
    _CHANNEL_SHIFT = 27,
    _FHSS_SHIFT = 28,
    _ANT_SIG_SHIFT = 29,
    _ANT_NOISE_SHIFT = 30,
    _LOCK_QUAL_SHIFT = 31,
    _TX_ATTN_SHIFT = 16,
    _DB_TX_ATTN_SHIFT = 17,
    _DBM_TX_POWER_SHIFT = 18,
    _ANTENNA_SHIFT = 19,
    _DB_ANT_SIG_SHIFT = 20,
    _DB_ANT_NOISE_SHIFT = 21,
    _RX_FLAGS_SHIFT = 22,
    _CHANNELPLUS_SHIFT = 10,
    _EXT_SHIFT = 0,
    -- Flags elements
    _FLAGS_SIZE = 2,
    _CFP_FLAG_SHIFT = 0,
    _PREAMBLE_SHIFT = 1,
    _WEP_SHIFT = 2,
    _FRAG_SHIFT = 3,
    _FCS_SHIFT = 4,
    _DATA_PAD_SHIFT = 5,
    _BAD_FCS_SHIFT = 6,
    _SHORT_GI_SHIFT = 7,
    -- Channel type
    _CHAN_TYPE_SIZE = 4,
    _CHANNEL_TYPE_SHIFT = 4,
    _CCK_SHIFT = 5,
    _OFDM_SHIFT = 6,
    _TWO_GHZ_SHIFT = 7,
    _FIVE_GHZ_SHIFT = 8,
    _PASSIVE_SHIFT = 9,
    _DYN_CCK_OFDM_SHIFT = 10,
    _GFSK_SHIFT = 11,
    _GSM_SHIFT = 12,
    _STATIC_TURBO_SHIFT = 13,
    _HALF_RATE_SHIFT = 14,
    _QUARTER_RATE_SHIFT = 15,
    -- Flags offsets and masks
    _FCS_SHIFT = 4,
    _FCS_MASK = 0x10
}
setmetatable(Radiotap, meta)

function Radiotap:init(buf)
    local o = {__buf = buf}
    setmetatable(o, {__index = self, __name = 'Radiotap'})
    o:unpack()
    return o
end

function Radiotap:unpack()
    local version, pad, len, present = string.unpack('I1I1I2I4', self.__buf)
    self.version = version
    self.pad = pad
    self.len = len
    self.present = utils.ntohls(present)
    self.data = string.sub(self.__buf, self.len + 1)
    --
    local present_need = {
        {'tsft', (self.present & self._TSFT_MASK) >> self._TSFT_SHIFT, 'I8'},
        {'flags', (self.present & self._FLAGS_MASK) >> self._FLAGS_SHIFT, 'I1'},
        {'rate', (self.present & self._RATE_MASK) >> self._RATE_SHIFT, 'I1'},
        {'channel', (self.present & self._CHANNEL_MASK) >> self._CHANNEL_SHIFT, 'I4'},
        {'fhss', (self.present & self._FHSS_MASK) >> self._FHSS_SHIFT, 'I2'},
        {'ant_sig', (self.present & self._ANT_SIG_MASK) >> self._ANT_SIG_SHIFT, 'I1'},
        {'ant_noise', (self.present & self._ANT_NOISE_MASK) >> self._ANT_NOISE_SHIFT, 'I1'},
        {'lock_qual', (self.present & self._LOCK_QUAL_MASK) >> self._LOCK_QUAL_SHIFT, 'I2'},
        {'tx_attn', (self.present & self._TX_ATTN_MASK) >> self._TSFT_SHIFT, 'I2'},
        {'db_tx_attn', (self.present & self._DB_TX_ATTN_MASK) >> self._DB_TX_ATTN_SHIFT, 'I2'},
        {'dbm_tx_power', (self.present & self._DBM_TX_POWER_MASK) >> self._DBM_TX_POWER_SHIFT, 'I1'},
        {'ant', (self.present & self._ANTENNA_MASK) >> self._ANTENNA_SHIFT, 'I1'},
        {'db_ant_sig', (self.present & self._DB_ANT_SIG_MASK) >> self._DB_ANT_SIG_SHIFT, 'I1'},
        {'db_ant_noise', (self.present & self._DB_ANT_NOISE_MASK) >> self._DB_ANT_NOISE_SHIFT, 'I1'},
        {'rx_flags', (self.present & self._RX_FLAGS_MASK) >> self._RX_FLAGS_SHIFT, 'I2'}
    }
    
    local pattern = ''
    local keys = {}
    for i, v in ipairs(present_need) do
        if v[2] > 0 then
            table.insert(keys, v[1])
            pattern = pattern .. v[3]
        end
    end

    local values = {string.unpack(pattern, string.sub(self.__buf, 9))}
    for i, key in ipairs(keys) do
        if values[i] ~= nil then
            self[key] = values[i]
        end
    end

    if self.channel ~= nil then
        self.channel_flags = (self.channel >> 16) & 0xffff
        self.channel = self.channel & 0xffff
    end
    if self.ant_sig ~= nil then
        self.ant_sig = self.ant_sig - 256
    end
end

function Radiotap:pack()
end

return Radiotap
