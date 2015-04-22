# PlugX RAT detection and analysis for Volatility 2.X
#
# Version 1.2
#
# Original Author: Fabien Perigaud <fabien.perigaud@cassidian.com>
# Author: Jason Jones <jason@jasonjon.es>
#
# This plugin is based on poisonivy.py by Andreas Schuster.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
from struct import unpack_from, calcsize, unpack, pack
from socket import inet_ntoa
from collections import defaultdict

import plugx_structures

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

# Simple rule:
#  - look for GULP signature at the beginning of a VAD (v1)
#  - look for /update?id=%8.8x
#  - look for (a push 0x2a0 or a "Proxy-Auth:" string) AND (use of a 0x713a8fc1 value or signature to identify v1 algorithm)
# When scanning, also check that the VAD is RWX
signatures = {
    'namespace1': 'rule plugx { \
                       strings: \
                       $v1a = { 47 55 4C 50 00 00 00 00 } \
                       $v1b = "/update?id=%8.8x" \
                       $v1algoa = { BB 33 33 33 33 2B } \
                       $v1algob = { BB 44 44 44 44 2B } \
                       $v2a = "Proxy-Auth:" \
                       $v2b = { 68 A0 02 00 00 } \
                       $v2k = { C1 8F 3A 71 } \
                       $v2p = { 68 A4 36 00 00 } \
                    condition: $v1a at 0 or $v1b or (($v2a or $v2b) and (($v1algoa and $v1algob) or $v2k or $v2p)) }'
}
#                       $v1algo = { BB 33 33 33 33 2B .. .. .. .. .. .. .. .. .. 09 BB 44 44 44 44 2B } \
class PlugXScan(taskmods.DllList):
    """Detect processes infected with PlugX"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('memory_model', '32bit') == '32bit')

    @staticmethod
    def get_vad_base(task, address):
        """ Get the VAD starting address """
        for vad in task.VadRoot.traverse():
            if vad.End > address >= vad.Start:
                return vad.Start
        return None

    @staticmethod
    def get_vad_perms(task, address):
        """ Get the VAD permissions """
        for vad in task.VadRoot.traverse():
            if vad.End > address >= vad.Start:
                return vad.u.VadFlags.Protection.v()
        return None

    def calculate(self):
        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        if not self.is_valid_profile(addr_space.profile):
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources=signatures)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)
            for hit, address in scanner.scan():
                if self.get_vad_perms(task, address) == 6: # RWX vad
                    vad_base_addr = self.get_vad_base(task, address)
                    yield task, vad_base_addr

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Name", "20"),
                                  ("PID", "8"),
                                  ("Data VA", "[addrpad]")])
        found = []
        for task, start in data:
            if (task, start) not in found:
                self.table_row(outfd, task.ImageFileName, task.UniqueProcessId, start)
                found.append((task, start))


class PlugXConfig(PlugXScan):
    """Locate and parse the PlugX configuration"""

    persistence = defaultdict(lambda: "Unknown", {0: "Service + Run Key", 1: "Service", 2: "Run key", 3: "None"})

    reg_hives = {
            0x80000002 : 'HKLM',
            0x80000001 : 'HKCU',
            0x80000000 : 'HKCR',
            0x80000003 : 'HKU',
            0x80000004 : 'HKPD',
            0x80000050 : 'HKPT',
            0x80000060 : 'HKPN',
            0x80000005 : 'HKCC',
            0x80000006 : 'HKDD',
        }

    @staticmethod
    def get_vad_end(task, address):
        """ Get the VAD end address """
        for vad in task.VadRoot.traverse():
            if address == vad.Start:
                return vad.End+1
        # This should never really happen
        return None

    @staticmethod
    def get_str_utf16le(buff):
        tstrend = buff.find("\x00\x00")
        tstr = buff[:tstrend + (tstrend & 1)]
        return tstr.decode('utf_16le')

    @staticmethod
    def get_proto(proto):
        ret = []
        if proto & 0x1:
            ret.append("TCP")
        if proto & 0x2:
            ret.append("HTTP")
        if proto & 0x4:
            ret.append("UDP")
        if proto & 0x8:
            ret.append("ICMP")
        if proto & 0x10:
            ret.append("DNS")
        if proto > 0x1f:
            ret.append("OTHER_UNKNOWN")
        return ' / '.join(ret)

    def parse_config(self, cfg_blob, cfg_sz, outfd):
        if cfg_sz in (0xbe4, 0x150c, 0x1510, 0x1b18, 0x1d18, 0x2540, 0x2a18, 0x2a20):
            cfg_blob = cfg_blob[12:] if cfg_sz == 0x1510 else cfg_blob[8:]

            # Flags
            desc = "<L" if cfg_sz == 0xbe4 else "<11L"
            flags = unpack_from(desc, cfg_blob)
            cfg_blob = cfg_blob[calcsize(desc):]
            outfd.write("\tFlags: %s\n" % " ".join(["%r" % (k != 0) for k in flags]))

            # 2 timers
            timer = unpack_from("4B", cfg_blob)
            cfg_blob = cfg_blob[4:]
            timer_str = ""
            if timer[0] != 0:
                timer_str += "%d days, " % timer[0]
            if timer[1] != 0:
                timer_str += "%d hours, " % timer[1]
            if timer[2] != 0:
                timer_str += "%d mins, " % timer[2]
            timer_str += "%d secs" % timer[3]
            outfd.write("\tTimer 1: %s\n" % timer_str)
            timer = unpack_from("4B", cfg_blob)
            cfg_blob = cfg_blob[4:]
            timer_str = ""
            if timer[0] != 0:
                timer_str += "%d days, " % timer[0]
            if timer[1] != 0:
                timer_str += "%d hours, " % timer[1]
            if timer[2] != 0:
                timer_str += "%d mins, " % timer[2]
            timer_str += "%d secs" % timer[3]
            outfd.write("\tTimer 2: %s\n" % timer_str)

            # Timetable
            timetable = cfg_blob[:0x2a0]
            cfg_blob = cfg_blob[0x2a0:]
            space = False
            for k in xrange(len(timetable)):
                if timetable[k] != "\x01":
                    space = True
            if space:
                outfd.write("\tTimeTable: Custom\n")

            # Custom DNS
            (dns1, dns2, dns3, dns4) = unpack_from("<4L", cfg_blob)
            custom_dns = cfg_blob[:0x10]
            cfg_blob = cfg_blob[0x10:]
            if dns1 not in (0, 0xffffffff):
                outfd.write("\tCustom DNS 1: %s\n" % inet_ntoa(custom_dns[:4]))
            if dns2 not in (0, 0xffffffff):
                outfd.write("\tCustom DNS 2: %s\n" % inet_ntoa(custom_dns[4:8]))
            if dns3 not in (0, 0xffffffff):
                outfd.write("\tCustom DNS 3: %s\n" % inet_ntoa(custom_dns[8:12]))
            if dns4 not in (0, 0xffffffff):
                outfd.write("\tCustom DNS 4: %s\n" % inet_ntoa(custom_dns[12:16]))

            # CC
            for k in xrange(4):
                (proto, cc_port, cc_address) = unpack_from('<2H64s', cfg_blob)
                cfg_blob = cfg_blob[0x44:]
                proto = self.get_proto(proto)
                cc_address = cc_address.split('\x00')[0]
                if cc_address != "":
                    outfd.write("\tC&C Address: %s:%d (%s)\n" % (str(cc_address), cc_port, proto))

            # Additional URLs
            for k in xrange(4):
                url = cfg_blob[:0x80].split('\x00')[0]
                cfg_blob = cfg_blob[0x80:]
                if len(url) > 0 and str(url) != "HTTP://":
                    outfd.write("\tURL %d: %s\n" % ((k+1), str(url)))

            # Proxies
            for k in xrange(4):
                ptype, port, proxy, user, passwd = unpack_from('<2H64s64s64s', cfg_blob)
                cfg_blob = cfg_blob[calcsize('<2H64s64s64s'):]
                if proxy[0] != '\x00':
                    outfd.write("\tProxy: %s:%d\n" % (proxy.split('\x00')[0], port))
                    if user[0] != '\x00':
                        outfd.write("\tProxy credentials: %s / %s\n" % (user, passwd))

            str_sz = 0x80 if cfg_sz == 0xbe4 else 0x200

            # Persistence
            if cfg_sz in (0x1b18, 0x1d18, 0x2540):
                persistence_type = unpack_from('<L', cfg_blob)[0]
                cfg_blob = cfg_blob[4:]
                persistence = self.persistence[persistence_type]
                outfd.write("\tPersistence Type: %s\n" % persistence)
            install_dir = self.get_str_utf16le(cfg_blob[:str_sz])
            cfg_blob = cfg_blob[str_sz:]
            outfd.write("\tInstall Dir: %s\n" % install_dir)
            # Service
            service_name = self.get_str_utf16le(cfg_blob[:str_sz])
            cfg_blob = cfg_blob[str_sz:]
            outfd.write("\tService Name: %s\n" % service_name)
            service_disp = self.get_str_utf16le(cfg_blob[:str_sz])
            cfg_blob = cfg_blob[str_sz:]
            outfd.write("\tService Disp: %s\n" % service_disp)
            service_desc = self.get_str_utf16le(cfg_blob[:str_sz])
            cfg_blob = cfg_blob[str_sz:]
            outfd.write("\tService Desc: %s\n" % service_desc)
            # Run key
            if cfg_sz in (0x1b18, 0x1d18, 0x2540):
                reg_hive = unpack_from('<L', cfg_blob)[0]
                cfg_blob = cfg_blob[4:]
                reg_key = self.get_str_utf16le(cfg_blob[:str_sz])
                cfg_blob = cfg_blob[str_sz:]
                reg_value = self.get_str_utf16le(cfg_blob[:str_sz])
                cfg_blob = cfg_blob[str_sz:]
                outfd.write("\tRegistry hive: %08x\n" % reg_hive)
                outfd.write("\tRegistry key: %s\n" % reg_key)
                outfd.write("\tRegistry value: %s\n" % reg_value)

            # Injection
            if cfg_sz in (0x1b18, 0x1d18, 0x2540):
                inject = unpack_from('<L', cfg_blob)[0]
                cfg_blob = cfg_blob[4:]
                outfd.write("\tInjection: %r\n" % (inject == 0))
                i = 4 if cfg_sz == 0x2540 else 1
                for k in xrange(i):
                    inject_in = self.get_str_utf16le(cfg_blob[:str_sz])
                    cfg_blob = cfg_blob[str_sz:]
                    if inject_in != "":
                        outfd.write("\tInjection process: %s\n" % inject_in)

            # Memo / Pass / Mutex
            if cfg_sz in (0x150c, 0x1510, 0x1b18, 0x1d18, 0x2540):
                online_pass = self.get_str_utf16le(cfg_blob[:str_sz])
                cfg_blob = cfg_blob[str_sz:]
                outfd.write("\tOnline Pass: %s\n" % online_pass)
                memo = self.get_str_utf16le(cfg_blob[:str_sz])
                cfg_blob = cfg_blob[str_sz:]
                outfd.write("\tMemo: %s\n" % memo)
            if cfg_sz in (0x1d18, 0x2540):
                mutex = self.get_str_utf16le(cfg_blob[:str_sz])
                cfg_blob = cfg_blob[str_sz:]
                outfd.write("\tMutex: %s\n" % mutex)

            # Screenshots
            if cfg_sz == 0x2540:
                (screenshots, freq, zoom, color, qual, days) = unpack_from('<6L', cfg_blob)
                cfg_blob = cfg_blob[calcsize('<6L'):]
                outfd.write("\tScreenshots: %r\n" % (screenshots != 0))
                outfd.write("\tScreenshots params: %d sec / Zoom %d / %d bits / Quality %d / Keep %d days\n" % (freq,
                                                                                                                zoom,
                                                                                                                color,
                                                                                                                qual,
                                                                                                                days))
                screen_path = self.get_str_utf16le(cfg_blob[:str_sz])
                cfg_blob = cfg_blob[str_sz:]
                outfd.write("\tScreenshots path: %s\n" % screen_path)

            # Lateral
            if cfg_sz == 0x2540:
                udp_enabled, udp_port, tcp_enabled, tcp_port = unpack_from('<4L', cfg_blob)
                if tcp_enabled == 1:
                    outfd.write("\tLateral TCP port: %d\n" % tcp_port)
                if udp_enabled == 1:
                    outfd.write("\tLateral UDP port: %d\n" % udp_port)

        # P2P Config detailed in JP-CERT blog post
        # added by jjones
        elif cfg_sz == 0x36a4:
            parsed = {}
            cfg = plugx_structures.PlugXP2PConfig.from_buffer_copy(cfg_blob)
            for f,t in cfg._fields_:
                if f.startswith(('unused','net_access')): continue
                v = getattr(cfg,f)
                if f=='mac_disable':
                    b = [x for x in v]
                    mac_str = '{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}'.format(*b)
                    outfd.write("\t{}: {}\n".format(f.replace('_',' ').title(),mac_str))
                elif getattr(v,'_type_',None):
                    for x in v:
                        if f == 'cnc':
                            if x.host:
                                outfd.write("\t{}: {}:{} ({})\n".format(f.replace('_',' ').title(),x.host,x.port,self.get_proto(x.proto)))
                        elif f == 'proxy':
                            if x.host:
                                outfd.write("\t{}: {}:{} ({} / {})\n".format(f.replace('_',' ').title(),x.host,x.port,x.user,x.passwd))
                        elif f == 'dns':
                            if x:
                                outfd.write("\t{}: {}\n".format(f.replace('_',' ').title(),inet_ntoa(pack("<I",x))))
                        elif len(getattr(x,'_fields_',[])) > 1:
                            a = {}
                            for y,z in x._fields_:
                                if getattr(x,y):
                                    outfd.write("\t{} {}: {}\n".format(f.replace('_',' ').title(),y.replace('_',' ').title(),y))
                        else:
                            if str(x):
                                outfd.write('\t{}: {}\n'.format(f.replace('_',' ').title(),x))
                elif f == 'persistence':
                    outfd.write('\t{}: {}\n'.format(f.replace('_',' ').title(),self.persistence[v]))
                elif f == 'reg_hive':
                    outfd.write('\t{}: {}\n'.format(f.replace('_',' ').title(),self.reg_hives.get(v,"Unknown")))
                elif 'end_scan' in f or 'start_scan' in f:
                    outfd.write('\t{}: {}\n'.format(f.replace('_',' ').title(),inet_ntoa(pack("<I",v))))
                else:
                    if str(v):
                        outfd.write('\t{}: {}\n'.format(f.replace('_',' ').title(),v))
        else:
            outfd.write("Config size 0x%04x not supported\n" % cfg_sz)

    def render_text(self, outfd, data):
        delim = '-' * 80

        found = []
        for task, start in data:
            if (task, start) not in found:
                found.append((task, start))
                #outfd.write("{0}\n".format(delim))
                proc_addr_space = task.get_process_address_space()
                data = proc_addr_space.zread(start, self.get_vad_end(task, start)-start)
                offset = data.find("\x68\xa0\x02\x00\x00")  # push 0x2a0

                if offset == -1:
                    continue
                while not (data[offset] == "\x68" and data[offset+5] == "\xe8") and offset > 0:
                    offset -= 1
                if data[offset] != "\x68":
                    continue

                # Now we're at:
                # push 0xxxxxx <- config address
                # call 0xxxxxx
                (config_addr, ) = unpack_from("=I", data, offset + 1)

                # Find previous push imm
                offset -= 1
                while not data[offset] == "\x68":
                    offset -= 1
                if data[offset] != "\x68":
                    continue

                (config_size, ) = unpack_from("=I", data, offset + 1)

                config_addr -= start
                config_blob = data[config_addr:config_addr+config_size]
                outfd.write("Process: %s (%d)\n\n" % (task.ImageFileName, task.UniqueProcessId))
                outfd.write("PlugX Config (0x%04x bytes):\n" % config_size)
                self.parse_config(config_blob, config_size, outfd)
