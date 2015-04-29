# Andromeda detection and analysis for Volatility 2.X
#
# Version 1.0
#
# Author: Jason Jones <jason@jasonjon.es>
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
import struct
import json
from collections import OrderedDict

can_run = False
try:
    from Crypto.Cipher import ARC4
    from capstone import *
    from capstone.x86 import *
    import yara
    can_run = True
except ImportError:
    pass

signatures = {
    'androm': """rule andromeda {
                       strings:
                        $fmt1 = "id:%lu|bid:%lu|os:%lu"
                        $fmt2 = "{\\"id\\":%lu,\\"bid\\":%lu,\\"os\\":%lu"
                        $s1 = "aReport"
                        $s2 = "aStart"
                        $s3 = "aUpdate"
                        $s4 = "User-Agent: Mozi1la/4.0"
                    condition: 1 of ($fmt*) and 1 of ($s*)
                }
            """
}
class Andromeda(taskmods.DllList):

    def brute_force_key(self,base,bid,data):
        # key and U
        ret = {}
        rc4_key = None
        url_data = data
        # typically first null byte after bid addr is end of the linked list
        list_end = data[bid:].find('\x00')+bid
        last_url = list_end - 1
        # walk up the linked list until we find a byte that matches distance to null
        # 
        attempts = 0
        for i in range(3):
            while last_url > bid and last_url + ord(data[last_url])+1 != list_end:
                last_url = last_url - 1
            if  i < 2 and last_url == bid:
                list_end = data[list_end+1:].find('\x00') + list_end + 1
                last_url = list_end - 1
            else: break

        if last_url == bid:
            return {}
        # crypted http:// 
        http = data[last_url+1:last_url+7]
        url_data = data[:last_url]
        # walk backwards until we find the beginning of the linked list
        while url_data.rfind(http) > 0:
            url_data = url_data[:url_data.rfind(http)-1]

        # take 16 byte chunks and see if they decrypt to http://
        rc4_key = None
        for i in range(bid,bid+0x200):
            k = data[i:i+16].encode('hex')[::-1]
            r = ARC4.new(k)
            d = r.decrypt(http)
            if d.startswith('http:/'):
                rc4_key = data[i:i+16].encode('hex')
        if rc4_key:
            ret['key'] = rc4_key
            ret['url'] = []
            i = len(url_data)
            while data[i] != '\x00':
                url_len = ord(data[i])
                crypted = data[i + 1:url_len + i + 1]
                r = ARC4.new(rc4_key[::-1])
                ret['url'].append(r.decrypt(crypted))
                i = url_len + i + 1
        return ret

    def get_config(self,base_addr,data):
        res = {}
        md = Cs(CS_ARCH_X86,CS_MODE_32)
        md.detail = True
        ph_str = data.find("id:%lu|bid:%lu")
        ph_str = data.find("""{"id":%lu,"bid":%lu,""") if ph_str == -1 else ph_str
        if ph_str == -1: return res
        fmt_str = data[ph_str:ph_str+data[ph_str:].find('\x00')]

        if "{" in fmt_str:
            ph_dict = OrderedDict([x.split(':') for x in fmt_str.replace('"','').replace('{','').replace('}','').split(",")])
        else:
            ph_dict = OrderedDict([x.split(':') for x in data[ph_str:ph_str+data[ph_str:].find('\x00')].split('|')])
        func_prolog = '\x55\x8b\xec'
        reg = {}
        if ph_str:
            ph_addr = base_addr + ph_str
            ph_push = "\x68" + struct.pack("<I",ph_addr)
            if data.find(ph_push):
                fun_start = data[:data.find(ph_push)].rfind(func_prolog)
                CODE = data[fun_start:fun_start+0x300]
                esp = []
                for i in md.disasm(CODE,base_addr+fun_start):
                    if i.mnemonic == 'push' and i.operands[0].imm == ph_addr:
                        break
                    elif i.mnemonic == 'push':
                        if i.operands[0].type == X86_OP_IMM:
                            esp.append(i.operands[0].imm)
                        elif i.operands[0].type == X86_OP_MEM:
                            esp.append(i.operands[0].mem.disp)
                        elif i.operands[0].type == X86_OP_REG:
                            esp.append(reg.get(i.reg_name(i.operands[0].value.reg)))
                    elif i.mnemonic == 'call': esp = []
                    elif i.mnemonic == 'mov' and len(i.operands) == 2 and i.operands[1].type == X86_OP_IMM:
                        reg[i.reg_name(i.operands[0].value.reg)] = i.operands[1].value.imm
                if i.operands and i.operands[0].imm == ph_addr:
                    phk = ph_dict.keys()
                    esp = esp[::-1]
                    for i in range(len(esp)):
                        if esp[i]:
                            res[phk[i]] = struct.unpack("<I",data[esp[i]-base_addr:esp[i]-base_addr+4])[0]
                        if phk[i] == 'bid':
                            s_addr = esp[i]+4
                            cnt = 0
                            key = None
                            enc_urls = []
                            try: res.update(self.brute_force_key(base_addr,s_addr-base_addr,data))
                            except: pass
                            # brute force failed, attempt tp locate via xrefs
                            if res.get('url',[]) == [] and 'bv' not in fmt_str:
                                for i in range(0x100):
                                    if data.find(struct.pack("<I",s_addr+i)) != -1:
                                        cnt += 1
                                        if cnt == 1:
                                            key = data[s_addr+i-base_addr:s_addr+i-base_addr+16].encode('hex')
                                            res['key'] = key
                                        elif cnt == 2:
                                            urldata = data[s_addr+i-base_addr:s_addr+i-base_addr+0x300]
                                            while urldata[0] != '\x00':
                                                l = ord(urldata[0])
                                                enc_url = urldata[1:l+1]
                                                urldata = urldata[l+1:]
                                                enc_urls.append(enc_url)
                                            res['url'] = []
                                            for enc_url in enc_urls:
                                                r = ARC4.new(key[::-1])
                                                res['url'].append(r.decrypt(enc_url))
                                            break
                            # fmt strs with bv typically not crypted
                            elif res.get('url',[]) == []:
                                res['key'] = data[s_addr-base_addr:s_addr-base_addr+32]
                                s_addr += 32
                                dword = struct.unpack("<I",data[s_addr-base_addr:s_addr-base_addr+4])[0]
                                res['url'] = []
                                while dword:
                                    res['url'].append( data[dword-base_addr:dword-base_addr+data[dword-base_addr:].find('\x00')] )
                                    s_addr += 4
                                    dword = struct.unpack("<I",data[s_addr-base_addr:s_addr-base_addr+4])[0]
        if res: res['fmt_str'] = fmt_str
        return res

    def get_vad(self, task, address):
        for vad in task.VadRoot.traverse():
            if vad.End > address >= vad.Start:
                return vad
        return None

    def calculate(self):
        if not can_run:
            debug.error("Yara, Capstone and PyCrypto must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        rules = yara.compile(sources=signatures)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)
            for hit, addr in scanner.scan():
                yield task, addr

    def render_text(self, outfd, data):
        vads = set()
        found = []
        for task, addr in data:
            vad = self.get_vad(task,addr)
            if vad in vads: continue
            vads.add(vad)
            proc_addr_space = task.get_process_address_space()
            data = proc_addr_space.zread(vad.Start, vad.End-vad.Start+1)

            config = self.get_config(vad.Start,data)
            if config:
                outfd.write("Andromeda Config Located\n")
                outfd.write("Process {} (PID: {}, VAD: 0x{:x})\n".format(task.ImageFileName, task.UniqueProcessId,vad.Start))
                for k,v in config.items():
                    if type(v) in (list,tuple,set):
                        for y in v:
                            outfd.write("\t{}: {}\n".format(k.replace('_',' ').title(),y))
                    elif type(v) == int:
                        outfd.write("\t{}: {:x}\n".format(k.replace('_',' ').title(),v))
                    else:
                        outfd.write("\t{}: {}\n".format(k.replace('_',' ').title(),v))

    def render_json(self, outfd, data):
        vads = set()
        found = []
        for task, addr in data:
            vad = self.get_vad(task,addr)
            if vad in vads: continue
            vads.add(vad)
            proc_addr_space = task.get_process_address_space()
            data = proc_addr_space.zread(vad.Start, vad.End-vad.Start+1)
            config = self.get_config(vad.Start,data)
            outfd.write("{}\n".format(json.dumps(config)))
