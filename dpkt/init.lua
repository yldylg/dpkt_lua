--
return {
    utils = require("dpkt.utils"),
    pcap = require("dpkt.pcap"),
    Ethernet = require("dpkt.ethernet"),
    ARP = require("dpkt.arp"),
    IP = require("dpkt.ip"),
    TCP = require("dpkt.tcp"),
    UDP = require("dpkt.udp"),
    Radiotap = require("dpkt.radiotap"),
    Dot11 = require("dpkt.ieee80211"),
    EAPOL = require("dpkt.eapol"),
    LLC = require("dpkt.llc")
}
