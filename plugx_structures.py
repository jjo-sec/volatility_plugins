from ctypes import *
import re

class PlugXCnC(Structure):
    _fields_ = [("proto",c_ushort),
                ("port",c_ushort),
                ("host",c_char*64),
               ]

class PlugXHTTP(Structure):
    _fields_ = [("url",c_ubyte*128),]

    def __str__(self):
        return re.sub(r"(\x00)+$","","".join([chr(x) for x in self.url]))

class PlugXProxy(Structure):
    _fields_ = [("type",c_ushort),
                ("port",c_short),
                ("host",c_char*64),
                ("user",c_char*64),
                ("passwd",c_char*64),
                ]
    def __str__(self):
        return "{}:{} ({} / {})".format(self.host,self.port,self.user,self.passwd)

class PlugXStr(Structure):
    _fields_ = [("string",c_ubyte*512)]

    def __str__(self):
        return re.sub(r"(\x00\x00)+$","".join([chr(x) for x in self.string])).decode("utf-16")

class PlugXP2PConfig(Structure):
    _fields_ = [("unused",c_ubyte*20),
                ("hide_dll",c_int32),
                ("keylogger",c_int32),
                ("unused2",c_ubyte*12),
                ("sleep1",c_uint32),
                ("sleep2",c_uint32),
                ("net_access",c_ubyte*672),
                ("dns",c_uint32*4),
                ("cnc",PlugXCnC*16),
                ("http",PlugXHTTP*16),
                ("proxy",PlugXProxy*4),
                ("persistence",c_int32),
                ("install_folder",PlugXStr),
                ("service_name",PlugXStr),
                ("service_display_name",PlugXStr),
                ("service_desc",PlugXStr),
                ("reg_hive",c_uint32),
                ("reg_key",PlugXStr),
                ("reg_value",PlugXStr),
                ("injection",c_int32),
                ("inject_process",PlugXStr*4),
                ("uac_bypass_injection",c_int32),
                ("uac_bypass_inject",PlugXStr*4),
                ("plugx_auth_str",PlugXStr),
                ("cnc_auth_str",PlugXStr),
                ("mutex",PlugXStr),
                ("screenshots",c_uint32),
                ('screenshots_sec',c_uint32),
                ('screenshots_zoom',c_uint32),
                ('screenshots_bits',c_uint32),
                ('screenshots_qual',c_uint32),
                ('screenshots_keep',c_uint32),
                ("screenshot_folder",PlugXStr),
                ("enable_tcp_p2p",c_int32),
                ("tcp_p2p_port",c_uint32),
                ("enable_udp_p2p",c_int32),
                ("udp_p2p_port",c_uint32),
                ("enable_icmp_p2p",c_uint32),
                ("icmp_p2p_port",c_uint32),
                ("enable_ipproto_p2p",c_int32),
                ("ipproto_p2p_port",c_int32),
                ("enable_p2p_scan",c_int32),
                ("p2p_start_scan1",c_uint32),
                ("p2p_start_scan2",c_uint32),
                ("p2p_start_scan3",c_uint32),
                ("p2p_start_scan4",c_uint32),
                ("p2p_end_scan1",c_uint32),
                ("p2p_end_scan2",c_uint32),
                ("p2p_end_scan3",c_uint32),
                ("p2p_end_scan4",c_uint32),
                ("mac_disable",c_ubyte*6),
                ("unused3",c_ubyte*2),
            ]
