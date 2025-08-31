#!/usr/bin/python
### AI generated code , no remark , ask AI analysis for you ..
import socket
import struct
import threading
import logging
import time
import random
import os
import sys
from datetime import datetime
from typing import Optional, List, Tuple
IPPROTO_SCTP = 132
SCCP_XUDT = 0x11                    
CONFIG = {
    'local_gt': '817085811990',
    'local_pc': 641,
    'remote_gt': '817090514560',
    'remote_pc': 2120,
    'route_context': 34,
    'ssn': 6,          
    'network_indicator': 3,                        
    'hlr_gt': '817085811990',                   
    'msc_gt': '817085811990',                           
    'vlr_gt': '817085811990',                   
    'log_level': 'INFO'                     
}
M3UA_MGMT_CLASS = 0
M3UA_TRANSFER_CLASS = 1
M3UA_SSNM_CLASS = 2
M3UA_ASPSM_CLASS = 3
M3UA_ASPTM_CLASS = 4
M3UA_RKM_CLASS = 5
M3UA_DATA = 1                 
M3UA_ASPUP = 1              
M3UA_ASPDN = 2
M3UA_BEAT = 3
M3UA_ASPUP_ACK = 4
M3UA_ASPDN_ACK = 5
M3UA_BEAT_ACK = 6
M3UA_ASPAC = 1              
M3UA_ASPIA = 2
M3UA_ASPAC_ACK = 3
M3UA_ASPIA_ACK = 4
M3UA_ERR = 0             
M3UA_NTFY = 1
M3UA_PARAM_NETWORK_APPEARANCE = 0x0200
M3UA_PARAM_ROUTING_CONTEXT = 0x0006
M3UA_PARAM_PROTOCOL_DATA = 0x0210
M3UA_PARAM_CORRELATION_ID = 0x0013
M3UA_PARAM_INFO_STRING = 0x0004
M3UA_PARAM_TRAFFIC_MODE_TYPE = 0x000b
M3UA_PARAM_ASP_IDENTIFIER = 0x0011
SCCP_UDT = 0x09           
SCCP_UDTS = 0x0A                   
SCCP_AI_PC_PRESENT = 0x01
SCCP_AI_ROUTING_GT = 0x00              
SCCP_AI_GT_PRESENT = 0x04             
SCCP_AI_SSN_PRESENT = 0x02              
TCAP_BEGIN = 0x62
TCAP_CONTINUE = 0x65
TCAP_END = 0x64
TCAP_ABORT = 0x67
MAP_SRI_SM = 45                           
MAP_SRI_SM_RESP = 45                           
MAP_MT_FSM = 44                        
MAP_MT_FSM_RESP = 44                           
MAP_MO_FSM = 46               
ASN1_SEQUENCE = 0x30
ASN1_CONTEXT_0 = 0x80
ASN1_CONTEXT_1 = 0x81
ASN1_CONTEXT_2 = 0x82
ASN1_INTEGER = 0x02
ASN1_OCTET_STRING = 0x04
class M3UAMessage:
    def __init__(self, version=1, msg_class=0, msg_type=0, length=8, data=b''):
        self.version = version
        self.reserved = 0
        self.msg_class = msg_class
        self.msg_type = msg_type
        self.length = length
        self.data = data
    def pack(self):
        header = struct.pack('!BBBBI', self.version, self.reserved,
                           self.msg_class, self.msg_type, self.length)
        return header + self.data
    @classmethod
    def unpack(cls, data):
        if len(data) < 8:
            return None
        version, reserved, msg_class, msg_type, length = struct.unpack('!BBBBI', data[:8])
        if length < 8 or length > len(data):
            return None
        msg_data = data[8:length] if length > 8 else b''
        return cls(version, msg_class, msg_type, length, msg_data)
class M3UAParameter:
    def __init__(self, tag, value=b''):
        self.tag = tag
        self.length = 4 + len(value)
        self.value = value
    def pack(self):
        padded_length = (self.length + 3) & ~3
        padding = b'\x00' * (padded_length - self.length)
        return struct.pack('!HH', self.tag, self.length) + self.value + padding
    @classmethod
    def unpack(cls, data):
        if len(data) < 4:
            return None, 0
        tag, length = struct.unpack('!HH', data[:4])
        if length < 4:
            return None, 0
        value_len = length - 4
        value = data[4:4 + value_len] if value_len > 0 else b''
        padded_length = (length + 3) & ~3
        return cls(tag, value), padded_length
class SCCPAddress:
    def __init__(self, gt=None, pc=None, ssn=None):
        self.gt = gt
        self.pc = pc
        self.ssn = ssn
    def pack(self):
        gti = 0x04 if self.gt else 0x00                                
        ai = (gti & 0x0F) << 2                              
        if self.ssn is not None:
            ai |= SCCP_AI_SSN_PRESENT       
        if self.pc is not None:
            ai |= SCCP_AI_PC_PRESENT       
        addr_data = struct.pack('!B', ai)
        if self.pc is not None:
            addr_data += struct.pack('<H', self.pc)
        if self.ssn is not None:
            addr_data += struct.pack('!B', self.ssn)
        if self.gt:
            digit_count = len(self.gt)
            es = 0x01 if (digit_count % 2 == 1) else 0x02                
            np_es = (0x01 << 4) | es                    
            nai = 0x04                       
            gt_data = struct.pack('!BBB', 0x00, np_es, nai)
            gt_digits = self.gt
            if digit_count % 2:
                gt_digits += 'F'                                 
            for i in range(0, len(gt_digits), 2):
                first = gt_digits[i]
                second = gt_digits[i + 1] if i + 1 < len(gt_digits) else 'F'
                d_low = 15 if first == 'F' else int(first)
                d_high = 15 if second == 'F' else int(second)
                gt_data += bytes([(d_high << 4) | d_low])                      
            addr_data += gt_data
        return struct.pack('!B', len(addr_data)) + addr_data
class MAPSIGTRANServer:
    def __init__(self, host='0.0.0.0', port=2915, log_level='INFO'):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.asp_states = {}
        self.transaction_id = 1
        self.active_transactions = {}
        self.log_level = log_level.upper()
        self.outgoing_dialogues = {}                                                          
        self.setup_logging()
        if self.log_level in ['INFO', 'DEBUG']:
            self.logger.info("=" * 60)
            self.logger.info("MAP SIGTRAN Server Configuration:")
            self.logger.info(f"  Local GT: {CONFIG['local_gt']}, PC: {CONFIG['local_pc']}")
            self.logger.info(f"  Remote GT: {CONFIG['remote_gt']}, PC: {CONFIG['remote_pc']}")
            self.logger.info(f"  Route Context: {CONFIG['route_context']}")
            self.logger.info(f"  HLR GT: {CONFIG['hlr_gt']}")
            self.logger.info(f"  MSC GT: {CONFIG['msc_gt']}")
            self.logger.info(f"  VLR GT: {CONFIG['vlr_gt']}")
            self.logger.info("=" * 60)
    def setup_logging(self):
        self.logger = logging.getLogger('MAPSIGTRANServer')
        self.logger.setLevel(logging.DEBUG)                                            
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        file_handler = logging.FileHandler('stp.log')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter('%(message)s')
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        if self.log_level != 'ERROR':                                       
            console_handler = logging.StreamHandler()
            if self.log_level == 'INFO':
                console_handler.setLevel(logging.INFO)
            elif self.log_level == 'DEBUG':
                console_handler.setLevel(logging.DEBUG)
            console_formatter = logging.Formatter('%(message)s')
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)
        self.logger.propagate = False
    def log_info(self, message):
        self.logger.info(message)
    def log_error(self, message):
        self.logger.error(message)
    def create_socket(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_SCTP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.log_info("Created native SCTP socket")
            return sock
        except Exception as e:
            self.log_error(f"Failed to create SCTP socket: {e}")
            return None
    def _is_ucs2_text(self, s: str) -> bool:
        return any(ord(ch) > 0x7F for ch in s)
    def _gsm7_septet_len_simple(self, s: str) -> int:
        return len(s)
    def _truncate_to_single_segment(self, text: str) -> str:
        if self._is_ucs2_text(text):
            return text[:70]                               
        if self._gsm7_septet_len_simple(text) > 160:
            return text[:160]
        return text
    def create_tcap_begin_dialogue_only(self, acn_oid: str = "0.4.0.0.1.0.21.3"):
        our_otid = struct.pack("!I", random.randint(0x10000000, 0xFFFFFFFF))
        otid = self.encode_asn1_tag_length(0x48, our_otid)
        dialogue_as_id = self._encode_oid("0.0.17.773.1.1.1")
        aaq_pv = self.encode_asn1_tag_length(0x80, b"\x07\x80")
        acn = self._encode_oid(acn_oid)                             
        aaq_acn = self.encode_asn1_tag_length(0xA1, acn)
        aaq = self.encode_asn1_tag_length(0x60, aaq_pv + aaq_acn)
        external = self.encode_asn1_tag_length(0x28, dialogue_as_id + self.encode_asn1_tag_length(0xA0, aaq))
        dialogue_portion = self.encode_asn1_tag_length(0x6B, external)
        begin = self.encode_asn1_tag_length(0x62, otid + dialogue_portion)
        return begin, our_otid
    def _gsm7_is_ext(ch: str) -> bool:
        return ch in '^{}\\[~]|€'
    def _gsm7_septet_len_exact(self, s: str) -> int:
        ext = set('^{}\\[]~]|€')
        length = 0
        for ch in s:
            length += 2 if ch in ext else 1
        return length
    def _gsm7_pack_septets(self, septets: List[int]) -> bytes:
        out = bytearray()
        acc = 0
        bits = 0
        for s in septets:
            acc |= (s & 0x7F) << bits
            bits += 7
            while bits >= 8:
                out.append(acc & 0xFF)
                acc >>= 8
                bits -= 8
        if bits:
            out.append(acc & 0xFF)
        return bytes(out)
    def _gsm7_pack_text(self, s: str) -> bytes:
        ext_map = {'^': 0x14, '{': 0x28, '}': 0x29, '\\': 0x2F, '[': 0x3C, '~': 0x3D, ']': 0x3E, '|': 0x40, '€': 0x65}
        septets = []
        for ch in s:
            if ch in ext_map:
                septets.append(0x1B)      
                septets.append(ext_map[ch])
            else:
                septets.append(ord(ch) & 0x7F)
        return self._gsm7_pack_septets(septets)
    def _gsm7_pack_with_udh(self, udh: bytes, text: str) -> Tuple[bytes, int]:
        udhl = len(udh)
        header = bytes([udhl]) + udh
        text_packed = self._gsm7_pack_text(text)                                
        text_septets = self._gsm7_septet_len_exact(text)                                   
        header_octets = len(header)                        
        pad_bits = (7 - ((header_octets * 8) % 7)) % 7            
        if pad_bits == 0:
            shifted = text_packed
        else:
            shifted_ba = bytearray()
            carry = 0
            for b in text_packed:
                out_byte = ((b << pad_bits) & 0xFF) | carry
                shifted_ba.append(out_byte)
                carry = (b >> (8 - pad_bits)) & ((1 << pad_bits) - 1)
            if carry:
                shifted_ba.append(carry)
            shifted = bytes(shifted_ba)
        header_septets = ((len(header) * 8) + 6) // 7
        udl_septets = header_septets + text_septets
        ud_bytes = header + shifted
        return ud_bytes, udl_septets
    def _extract_component_portion(self, tcap_data: bytes) -> Optional[bytes]:
        def _read_tlv(buf, off):
            if off >= len(buf): return None
            tag = buf[off]; off += 1
            if off >= len(buf): return None
            first = buf[off]; off += 1
            if first & 0x80:
                n = first & 0x7F
                if n == 0 or off + n > len(buf): return None
                length = int.from_bytes(buf[off:off+n], 'big'); off += n
            else:
                length = first
            val_start, val_end = off, off + length
            if val_end > len(buf): return None
            return tag, length, val_start, val_end, val_end
        top = _read_tlv(tcap_data, 0)
        if not top: return None
        _, _, tcap_vs, tcap_ve, _ = top
        off = tcap_vs
        while off < tcap_ve:
            tlv = _read_tlv(tcap_data, off)
            if not tlv: break
            tag, length, vs, ve, off = tlv
            if tag == 0x6C:
                header = bytearray()
                value = tcap_data[vs:ve]
                if length < 0x80:
                    header += bytes([0x6C, length])
                else:
                    lb = length.to_bytes((length.bit_length()+7)//8, 'big')
                    header += bytes([0x6C, 0x80 | len(lb)]) + lb
                return bytes(header) + value
        return None
    def _on_dialogue_end_progress(self, tcap_data: bytes):
        try:
            dtid = self.extract_dtid_from_tcap(tcap_data)
            if not dtid:
                return
            key = dtid.hex()
            dlg = self.outgoing_dialogues.get(key)
            if not dlg:
                return
            if 'components' not in dlg:
                single = dlg.get('component')
                if single:
                    dlg['components'] = [single]
                    dlg['next'] = 0
                    try:
                        del dlg['component']
                    except Exception:
                        pass
            comps = dlg.get('components', [])
            idx = int(dlg.get('next', 0))
            total = len(comps)
            if idx >= total:
                try:
                    del self.outgoing_dialogues[key]
                except Exception:
                    pass
                self.log_info("MO handshake: peer TC-END received; queue already empty.")
                return
            component = comps[idx]
            called_gt = dlg.get('called_gt')
            calling_gt = dlg.get('calling_gt')
            self._debug_dump_mo_fsm_component(component, f"Reopen-Begin seg {idx + 1}/{total}")
            begin, new_otid = self._tcap_begin_with_component(component, "0.4.0.0.1.0.21.3")
            ok = self._send_sccp_tcap_on_active(begin, called_gt, calling_gt)
            if ok:
                new_key = new_otid.hex()
                new_state = {
                    'our_otid': new_otid,
                    'peer_otid': None,
                    'called_gt': called_gt,
                    'calling_gt': calling_gt,
                    'components': comps,
                    'next': idx + 1,
                }
                self.outgoing_dialogues[new_key] = new_state
                try:
                    del self.outgoing_dialogues[key]
                except Exception:
                    pass
                self.log_info(
                    f"MO handshake: Peer closed dialogue (TC-END). "
                    f"Reopened new BEGIN and sent segment {idx + 1}/{total} "
                    f"(old_otid={key}, new_otid={new_key})."
                )
            else:
                self.log_error("MO handshake: Failed to send new BEGIN for next segment after peer TC-END.")
        except Exception as e:
            self.log_error(f"MO handshake (_on_dialogue_end_progress) error: {e}")
    def _tcap_begin_with_component(self, component: bytes, acn_oid: str = "0.4.0.0.1.0.21.3") -> Tuple[bytes, bytes]:
        our_otid = struct.pack("!I", random.randint(0x10000000, 0xFFFFFFFF))
        otid = self.encode_asn1_tag_length(0x48, our_otid)
        dialogue_as_id = self._encode_oid("0.0.17.773.1.1.1")
        aaq_pv = self.encode_asn1_tag_length(0x80, b"\x07\x80")
        acn = self._encode_oid(acn_oid)                                        
        aaq_acn = self.encode_asn1_tag_length(0xA1, acn)
        aaq = self.encode_asn1_tag_length(0x60, aaq_pv + aaq_acn)
        external = self.encode_asn1_tag_length(0x28, dialogue_as_id + self.encode_asn1_tag_length(0xA0, aaq))
        dialogue_portion = self.encode_asn1_tag_length(0x6B, external)
        begin_body = otid + dialogue_portion + component
        begin = self.encode_asn1_tag_length(0x62, begin_body)
        return begin, our_otid
    def _read_tlv(self, buf: bytes, off: int):
        if off >= len(buf):
            return None
        tag = buf[off]
        off += 1
        if off >= len(buf):
            return None
        first = buf[off]
        off += 1
        if first & 0x80:
            n = first & 0x7F
            if n == 0 or off + n > len(buf):
                return None
            length = int.from_bytes(buf[off:off + n], 'big')
            off += n
        else:
            length = first
        val_start = off
        val_end = off + length
        if val_end > len(buf):
            return None
        next_off = val_end
        return (tag, length, val_start, val_end, next_off)
    def _inspect_tpdu(self, tpdu: bytes, context: str):
        try:
            if not tpdu or len(tpdu) < 2:
                self.log_error(f"[TPDU/{context}] too short: {len(tpdu)}")
                return
            fo = tpdu[0]
            mti = fo & 0x03
            udhi = (fo & 0x40) != 0
            mr = tpdu[1]
            idx = 2
            if idx >= len(tpdu):
                self.log_error(f"[TPDU/{context}] truncated before DA length.")
                return
            da_len_digits = tpdu[idx]; idx += 1
            if idx >= len(tpdu):
                self.log_error(f"[TPDU/{context}] truncated before TOA.")
                return
            toa = tpdu[idx]; idx += 1
            da_octets = (da_len_digits + 1) // 2
            if idx + da_octets > len(tpdu):
                self.log_error(f"[TPDU/{context}] DA digits truncated: need {da_octets}, have {len(tpdu) - idx}")
                return
            da_tbcd = tpdu[idx:idx + da_octets]
            idx += da_octets
            if idx + 2 > len(tpdu):
                self.log_error(f"[TPDU/{context}] missing PID/DCS.")
                return
            pid = tpdu[idx]; dcs = tpdu[idx + 1]; idx += 2
            if idx >= len(tpdu):
                self.log_error(f"[TPDU/{context}] missing UDL.")
                return
            udl = tpdu[idx]; idx += 1
            self.log_info(f"[TPDU/{context}] FO=0x{fo:02X} (MTI={mti}, UDHI={'1' if udhi else '0'}) MR={mr} "
                          f"DA_len(digits)={da_len_digits} TOA=0x{toa:02X} PID=0x{pid:02X} DCS=0x{dcs:02X} UDL={udl}")
            if idx >= len(tpdu):
                self.log_error(f"[TPDU/{context}] no UD bytes present.")
                return
            ud = tpdu[idx:]
            if not udhi:
                self.log_info(f"[TPDU/{context}] UDHI=0; UD len={len(ud)} octets (no UDH).")
                return
            if len(ud) < 1:
                self.log_error(f"[TPDU/{context}] UD too short for UDHL.")
                return
            udhl = ud[0]
            if 1 + udhl > len(ud):
                self.log_error(f"[TPDU/{context}] UDH truncated: UDHL={udhl}, available={len(ud)-1}")
                return
            udh = ud[1:1 + udhl]
            user_data = ud[1 + udhl:]
            self.log_info(f"[TPDU/{context}] UD len={len(ud)} octets; UDHL={udhl}; UDH={udh.hex()} "
                          f"user_data_octets={len(user_data)}")
            p = 0
            total = seq = None
            while p + 2 <= len(udh):
                iei = udh[p]; p += 1
                ielen = udh[p]; p += 1
                if p + ielen > len(udh):
                    break
                ieval = udh[p:p + ielen]; p += ielen
                if iei == 0x00 and ielen == 3:
                    total = ieval[1]; seq = ieval[2]
                    break
                elif iei == 0x08 and ielen == 4:
                    total = ieval[2]; seq = ieval[3]
                    break
            if total is not None and seq is not None:
                self.log_info(f"[TPDU/{context}] Concat IE: parts={total} part={seq}")
            else:
                self.log_info(f"[TPDU/{context}] Concat IE: not found")
            if dcs == 0x00:
                header_octets = 1 + udhl
                pad_bits = (7 - ((header_octets * 8) % 7)) % 7
        except Exception as e:
            self.log_error(f"[TPDU/{context}] inspector error: {e}")
    def _debug_dump_mo_fsm_component(self, component_portion: bytes, context: str):
        try:
            off = 0
            tlv = self._read_tlv(component_portion, off)
            if not tlv:
                self.log_error(f"[MO-COMP/{context}] cannot read top TLV")
                return
            tag, length, vs, ve, off = tlv
            if tag != 0x6C:                
                vs = 0; ve = len(component_portion)
            comp_bytes = component_portion[vs:ve]
            inner = self._read_tlv(comp_bytes, 0)
            if not inner:
                self.log_error(f"[MO-COMP/{context}] cannot read inner component")
                return
            ctag, clen, cvs, cve, _ = inner
            if ctag != 0xA1:
                self.log_info(f"[MO-COMP/{context}] first component not Invoke (tag=0x{ctag:02X})")
            off2 = cvs
            first = self._read_tlv(comp_bytes, off2)
            invoke_id = None
            if first and first[0] == 0x02:
                _, _, fvs, fve, off2 = first
                try:
                    invoke_id = int.from_bytes(comp_bytes[fvs:fve], "big")
                except Exception:
                    invoke_id = None
            smrpui = None
            while off2 < cve:
                node = self._read_tlv(comp_bytes, off2)
                if not node:
                    break
                nt, nl, nvs, nve, off2 = node
                if nt in (0x30, 0xA0, 0xA1, 0xA2, 0xA3):
                    scan = nvs
                    while scan < nve:
                        leaf = self._read_tlv(comp_bytes, scan)
                        if not leaf:
                            break
                        lt, ll, lvs, lve, scan = leaf
                        if lt == 0x04:                           
                            smrpui = comp_bytes[lvs:lve]
                            break
                if smrpui is not None:
                    break
            if smrpui is None:
                self.log_error(f"[MO-COMP/{context}] sm-RP-UI not found")
                return
            looks_rpdu = (len(smrpui) >= 1 and (smrpui[0] & 0x3F) == 0x01)                            
            head = smrpui[:32].hex()
            if looks_rpdu:
                i = 2                      
                while i + 2 <= len(smrpui):
                    iei = smrpui[i]; i += 1
                    if i >= len(smrpui): break
                    iel = smrpui[i]; i += 1
                    if i + iel > len(smrpui): break
                    iev = smrpui[i:i + iel]; i += iel
                    if iei == 0x04 and len(iev) >= 1:
                        tpdu_len = iev[0]
                        if 1 + tpdu_len <= len(iev):
                            tpdu = iev[1:1 + tpdu_len]
                        else:
                            tpdu = iev[1:]
                        self._inspect_tpdu(tpdu, context + "/RPDU.TPDU")
                        break
            else:
                self._inspect_tpdu(smrpui, context + "/TPDU")
        except Exception as e:
            self.log_error(f"[MO-COMP/{context}] error: {e}")
    def _on_dialogue_continue(self, tcap_data: bytes):
        dtid = self.extract_dtid_from_tcap(tcap_data)
        otid = self.extract_otid_from_tcap(tcap_data)
        if not dtid or not otid:
            return
        key = dtid.hex()
        dlg = self.outgoing_dialogues.get(key)
        if not dlg:
            return
        if 'components' not in dlg:
            single = dlg.get('component')
            if single:
                dlg['components'] = [single]
                dlg['next'] = 0
                try:
                    del dlg['component']
                except Exception:
                    pass
            else:
                self.log_error("MO handshake: No components queued to send.")
                del self.outgoing_dialogues[key]
                return
        our_otid = dlg.get('our_otid')
        peer_otid = dlg.get('peer_otid') or otid                                     
        dlg['peer_otid'] = peer_otid                                  
        comps = dlg.get('components', [])
        idx = int(dlg.get('next', 0))
        total = len(comps)
        if idx >= total:            
            try:
                del self.outgoing_dialogues[key]
            except Exception:
                pass
            return
        component = comps[idx]
        last = (idx == total - 1)
        try:
            if last:
                tcap_body = self.encode_asn1_tag_length(0x49, peer_otid) + component
                tcap_msg = self.encode_asn1_tag_length(0x64, tcap_body)      
            else:
                if not our_otid or not peer_otid:
                    self.log_error("MO handshake: missing our_otid or peer_otid for CONTINUE.")
                    return
                tcap_body = (self.encode_asn1_tag_length(0x48, our_otid) +
                             self.encode_asn1_tag_length(0x49, peer_otid) +
                             component)
                tcap_msg = self.encode_asn1_tag_length(0x65, tcap_body)           
        except Exception as e:
            self.log_error(f"MO handshake: TCAP build error: {e}")
            return
        called_gt = dlg.get('called_gt')
        calling_gt = dlg.get('calling_gt')
        ok = self._send_sccp_tcap_on_active(tcap_msg, called_gt, calling_gt)
        if ok:            
            dlg['next'] = idx + 1
            if last:
                try:
                    del self.outgoing_dialogues[key]
                except Exception:
                    pass
        else:
            self.log_error("MO handshake: Failed to send next segment.")
    def create_m3ua_response(self, req_class, req_type, parameters=None):
        if parameters is None:
            parameters = []
        response_map = {
            (M3UA_ASPSM_CLASS, M3UA_ASPUP): M3UA_ASPUP_ACK,
            (M3UA_ASPSM_CLASS, M3UA_ASPDN): M3UA_ASPDN_ACK,
            (M3UA_ASPSM_CLASS, M3UA_BEAT): M3UA_BEAT_ACK,
            (M3UA_ASPTM_CLASS, M3UA_ASPAC): M3UA_ASPAC_ACK,
            (M3UA_ASPTM_CLASS, M3UA_ASPIA): M3UA_ASPIA_ACK,
        }
        if (req_class, req_type) not in response_map:
            return None
        resp_type = response_map[(req_class, req_type)]
        param_data = b''.join([p.pack() for p in parameters])
        msg_length = 8 + len(param_data)
        return M3UAMessage(version=1, msg_class=req_class,
                          msg_type=resp_type, length=msg_length,
                          data=param_data)
    def generate_imsi(self, msisdn):
        mcc = "440"        
        mnc = "11"                 
        if len(msisdn) >= 9:
            msin = msisdn[-9:]                     
        else:
            msin = msisdn.zfill(9)                 
        imsi = mcc + mnc + msin
        if len(imsi) != 15:
            imsi = imsi[:15].ljust(15, '0')
        return imsi
    def encode_bcd_digits(self, digits_str):
        digits = digits_str
        if len(digits) % 2:
            digits += 'F'
        out = bytearray()
        for i in range(0, len(digits), 2):
            first = digits[i]             
            second = digits[i+1]              
            d_low = 15 if first == 'F' else int(first)
            d_high = 15 if second == 'F' else int(second)
            out.append((d_high << 4) | d_low)
        return bytes(out)
    def encode_asn1_tag_length(self, tag: int, data: bytes) -> bytes:
        length = len(data)
        if length < 0x80:
            return bytes([tag, length]) + data
        length_bytes = []
        tmp = length
        while tmp > 0:
            length_bytes.insert(0, tmp & 0xFF)
            tmp >>= 8
        if len(length_bytes) > 127:
            raise ValueError("Length too large for ASN.1 encoding")
        return bytes([tag, 0x80 | len(length_bytes)]) + bytes(length_bytes) + data
    def _encode_oid(self, dotted: str) -> bytes:
        parts = [int(x) for x in dotted.split('.')]
        if len(parts) < 2:
            raise ValueError("OID must have at least two arcs")
        first = 40 * parts[0] + parts[1]
        body = [first]
        for arc in parts[2:]:
            if arc < 0x80:
                body.append(arc)
            else:
                stack = []
                while arc > 0:
                    stack.insert(0, (arc & 0x7F) | 0x80)
                    arc >>= 7
                stack[-1] &= 0x7F
                body.extend(stack)
        value = bytes(body)
        return self.encode_asn1_tag_length(0x06, value)                    
    def _build_tcap_dialogue_portion_aare(self, acn_oid: str = "0.4.0.0.1.0.20.3") -> bytes:
        dialogue_as_id = self._encode_oid("0.0.17.773.1.1.1")
        aare_pv = self.encode_asn1_tag_length(0x80, b"\x07\x80")
        acn_inner = self._encode_oid(acn_oid)
        aare_acn = self.encode_asn1_tag_length(0xA1, acn_inner)
        aare_result = self.encode_asn1_tag_length(0xA2, b"\x02\x01\x00")            
        rsd_inner = self.encode_asn1_tag_length(0xA1, b"\x02\x01\x00")
        aare_rsd = self.encode_asn1_tag_length(0xA3, rsd_inner)
        aare_payload = aare_pv + aare_acn + aare_result + aare_rsd
        aare = self.encode_asn1_tag_length(0x61, aare_payload)
        single_asn1 = self.encode_asn1_tag_length(0xA0, aare)
        external = self.encode_asn1_tag_length(0x28, dialogue_as_id + single_asn1)
        dialogue_portion = self.encode_asn1_tag_length(0x6B, external)
        return dialogue_portion
    def extract_dtid_from_tcap(self, tcap_data: bytes) -> bytes:
        try:
            def _read_tlv(buf, off):
                if off >= len(buf):
                    return None
                tag = buf[off]
                off += 1
                if off >= len(buf):
                    return None
                first = buf[off]
                off += 1
                if first & 0x80:
                    n = first & 0x7F
                    if n == 0 or off + n > len(buf):
                        return None
                    length = int.from_bytes(buf[off:off + n], 'big')
                    off += n
                else:
                    length = first
                val_end = off + length
                if val_end > len(buf):
                    return None
                return tag, length, off, val_end, val_end
            top = _read_tlv(tcap_data, 0)
            if not top:
                return None
            tcap_tag, tcap_len, tcap_vs, tcap_ve, _ = top
            off = tcap_vs
            while off < tcap_ve:
                tlv = _read_tlv(tcap_data, off)
                if not tlv:
                    break
                tag, length, vs, ve, off = tlv
                if tag == 0x49:       
                    return tcap_data[vs:ve]
            return None
        except Exception as e:
            self.log_error(f"Error extracting DTID from TCAP: {e}")
            return None
    def extract_otid_from_tcap(self, tcap_data: bytes) -> bytes:
      try:
        def _read_tlv(buf, off):
            if off >= len(buf): return None
            tag = buf[off]; off += 1
            if off >= len(buf): return None
            first = buf[off]; off += 1
            if first & 0x80:
                n = first & 0x7F
                if n == 0 or off + n > len(buf): return None
                length = int.from_bytes(buf[off:off + n], 'big')
                off += n
            else:
                length = first
            val_end = off + length
            if val_end > len(buf): return None
            return tag, length, off, val_end, val_end
        top = _read_tlv(tcap_data, 0)
        if not top: return None
        _, _, tcap_vs, tcap_ve, _ = top
        off = tcap_vs
        while off < tcap_ve:
            tlv = _read_tlv(tcap_data, off)
            if not tlv: break
            tag, _, vs, ve, off = tlv
            if tag == 0x48:       
                return tcap_data[vs:ve]
        return None
      except Exception as e:
        self.log_error(f"Error extracting OTID from TCAP: {e}")
        return None
    def create_mt_fsm_response(self, invoke_id: int, op_code: int, orig_transaction_id: bytes, tcap_data: bytes):
      try:
        if len(tcap_data) == 0:
            self.log_error("Empty TCAP data")
            return None
        incoming_tcap_tag = tcap_data[0]
        tcap_type = {0x62: 'BEGIN', 0x64: 'END', 0x65: 'CONTINUE', 0x67: 'ABORT'}.get(incoming_tcap_tag, 'Unknown')
        is_final_segment = self.detect_final_segment(tcap_data, invoke_id)
        response_tcap_tag = 0x64
        if incoming_tcap_tag == 0x62:             
            response_tcap_tag = 0x64           
        elif incoming_tcap_tag == 0x65:                
            if is_final_segment:
                response_tcap_tag = 0x64           
            else:
                response_tcap_tag = 0x65                
        else:
            response_tcap_tag = 0x64
        invoke_id_enc = self.encode_asn1_tag_length(0x02, bytes([invoke_id & 0xFF]))
        op_code_enc = self.encode_asn1_tag_length(0x02, bytes([op_code & 0xFF]))                      
        sm_rp_ui = self.encode_asn1_tag_length(0x04, b"\x00\x00")
        sm_rp_ui_pack = self.encode_asn1_tag_length(0x30, sm_rp_ui)
        result_seq = self.encode_asn1_tag_length(0x30, op_code_enc + sm_rp_ui_pack)
        rrl_content = invoke_id_enc
        component = self.encode_asn1_tag_length(0xA2, rrl_content)                       
        component_portion = self.encode_asn1_tag_length(0x6C, component)                    
        if response_tcap_tag == 0x65:                
            incoming_dtid = self.extract_dtid_from_tcap(tcap_data)
            incoming_otid = self.extract_otid_from_tcap(tcap_data)
            if incoming_tcap_tag == 0x65 and incoming_dtid and incoming_otid:
                otid_value = incoming_dtid
                dtid_value = incoming_otid
            else:                 
                otid_value = struct.pack('!I', random.randint(0x10000000, 0xFFFFFFFF))
                dtid_value = orig_transaction_id if orig_transaction_id else struct.pack('!I', random.randint(0x10000000, 0xFFFFFFFF))
            otid = self.encode_asn1_tag_length(0x48, otid_value)       
            dtid = self.encode_asn1_tag_length(0x49, dtid_value)       
            transaction_ids = otid + dtid
        else:           
            peer_otid = self.extract_otid_from_tcap(tcap_data)                                  
            if peer_otid and 1 <= len(peer_otid) <= 4:
                dtid_value = peer_otid
            elif orig_transaction_id and 1 <= len(orig_transaction_id) <= 4:
                dtid_value = orig_transaction_id                                      
            else:
                self.log_error("Cannot determine DTID for TCAP END (no peer OTID available).")
                return None
            dtid = self.encode_asn1_tag_length(0x49, dtid_value)
            transaction_ids = dtid
        if incoming_tcap_tag == 0x65:
           tcap_data_content = transaction_ids + component_portion
        else:
          dialogue_portion = self._build_tcap_dialogue_portion_aare("0.4.0.0.1.0.25.3")             
          tcap_data_content = transaction_ids + dialogue_portion + component_portion
        tcap_response = self.encode_asn1_tag_length(response_tcap_tag, tcap_data_content)
        response_type = {0x64: 'END', 0x65: 'CONTINUE'}.get(response_tcap_tag, 'Unknown')
        return tcap_response
      except Exception as e:
        self.log_error(f"Error creating MT-FSM Response: {e}")
        return None
    def detect_final_segment(self, tcap_data: bytes, invoke_id: int) -> bool:
        try:
            is_final = True                     
            def _read_tlv(buf, off):
                if off >= len(buf): return None
                tag = buf[off]; off += 1
                if off >= len(buf): return None
                first = buf[off]; off += 1
                if first & 0x80:
                    n = first & 0x7F
                    if n == 0 or off + n > len(buf): return None
                    length = int.from_bytes(buf[off:off + n], 'big')
                    off += n
                else:
                    length = first
                val_end = off + length
                if val_end > len(buf): return None
                return tag, length, off, val_end, val_end
            tcap_tlv = _read_tlv(tcap_data, 0)
            if not tcap_tlv:
                return is_final
            _, _, tcap_vs, tcap_ve, _ = tcap_tlv
            off = tcap_vs
            component_portion_data = None
            while off < tcap_ve:
                tlv = _read_tlv(tcap_data, off)
                if not tlv: break
                tag, length, vs, ve, off = tlv
                if tag == 0x6C:
                    component_portion_data = tcap_data[vs:ve]
                    break
            if not component_portion_data:
                return is_final
            comp_off = 0
            found_param_len = None
            while comp_off < len(component_portion_data):
                comp_tlv = _read_tlv(component_portion_data, comp_off)
                if not comp_tlv: break
                comp_tag, comp_len, comp_vs, comp_ve, comp_off = comp_tlv
                if comp_tag == 0xA1:         
                    invoke_data = component_portion_data[comp_vs:comp_ve]
                    inv_off = 0
                    id_tlv = _read_tlv(invoke_data, inv_off)
                    if id_tlv and id_tlv[0] == 0x02:
                        _, _, id_vs, id_ve, inv_off = id_tlv
                        parsed_invoke_id = int.from_bytes(invoke_data[id_vs:id_ve], "big")
                        if parsed_invoke_id == invoke_id:
                            while inv_off < len(invoke_data):
                                param_tlv = _read_tlv(invoke_data, inv_off)
                                if not param_tlv: break
                                param_tag, param_len, param_vs, param_ve, inv_off = param_tlv
                                if param_tag in (0x30, 0xA0):                                        
                                    found_param_len = param_ve - param_vs
                                    mt_fsm_param = invoke_data[param_vs:param_ve]
                                    is_final = self.analyze_mt_fsm_parameters(mt_fsm_param)
                                    break
                            break
            return is_final
        except Exception as e:
            self.log_error(f"Error in final segment detection: {e}")
            self.log_info("MT-FSM detect summary: error path -> final=Yes")
            return True
    def analyze_mt_fsm_parameters(self, mt_fsm_param: bytes) -> bool:
        try:
            def _read_tlv(buf, off):
                if off >= len(buf): return None
                tag = buf[off]; off += 1
                if off >= len(buf): return None
                first = buf[off]; off += 1
                if first & 0x80:
                    n = first & 0x7F
                    if n == 0 or off + n > len(buf): return None
                    length = int.from_bytes(buf[off:off+n], 'big'); off += n
                else:
                    length = first
                end = off + length
                if end > len(buf): return None
                return tag, length, off, end, end                                         
            sm_rp_ui = None
            off = 0
            while off < len(mt_fsm_param):
                tlv = _read_tlv(mt_fsm_param, off)
                if not tlv: break
                tag, _, vs, ve, off = tlv
                if tag == 0x82:                            
                    sm_rp_ui = mt_fsm_param[vs:ve]
                    break
                elif tag == 0xA2:                                             
                    inner = _read_tlv(mt_fsm_param, vs)
                    if inner and inner[0] == 0x04:
                        _, _, ivs, ive, _ = inner
                        sm_rp_ui = mt_fsm_param[ivs:ive]
                        break
                    sm_rp_ui = mt_fsm_param[vs:ve]
                    break
            if not sm_rp_ui:
                off = 0
                while off < len(mt_fsm_param):
                    tlv = _read_tlv(mt_fsm_param, off)
                    if not tlv: break
                    tag, _, vs, ve, off = tlv
                    if tag == 0x04 and (ve - vs) >= 10:
                        sm_rp_ui = mt_fsm_param[vs:ve]
                        break
            if not sm_rp_ui or len(sm_rp_ui) == 0:
                return True
            rpdu_detected = False
            rp_user_len = None
            tpdu = sm_rp_ui
            if len(sm_rp_ui) >= 3 and (sm_rp_ui[0] & 0x3F) == 0x01:
                rpdu_detected = True
                i = 2                        
                while i + 2 <= len(sm_rp_ui):
                    iei = sm_rp_ui[i]; i += 1
                    if i >= len(sm_rp_ui): break
                    ie_len = sm_rp_ui[i]; i += 1
                    if i + ie_len > len(sm_rp_ui): break
                    ie_val = sm_rp_ui[i:i+ie_len]; i += ie_len
                    if iei == 0x04:               
                        if len(ie_val) >= 1:
                            rp_user_len = ie_val[0]
                            if 1 + rp_user_len <= len(ie_val):
                                tpdu = ie_val[1:1+rp_user_len]
                            else:
                                tpdu = ie_val[1:]
                        break
            if len(tpdu) == 0:
                return True
            fo = tpdu[0]
            mti = fo & 0x03                             
            udhi = (fo & 0x40) != 0            
            if mti != 0x00:
                return True
            if not udhi:
                return True
            idx = 1
            if idx >= len(tpdu):
                return True
            oa_len_digits = tpdu[idx]; idx += 1
            if idx >= len(tpdu):
                return True
            toa = tpdu[idx]; idx += 1
            addr_bytes = (oa_len_digits + 1) // 2
            if idx + addr_bytes > len(tpdu):
                return True
            idx += addr_bytes
            if idx + 2 > len(tpdu):
                return True
            pid = tpdu[idx]; dcs = tpdu[idx+1]; idx += 2
            if idx + 7 > len(tpdu):
                return True
            scts = tpdu[idx:idx+7]; idx += 7
            if idx >= len(tpdu):
                return True
            udl = tpdu[idx]; idx += 1
            if idx >= len(tpdu):
                return True
            ud = tpdu[idx:]                                                                           
            if len(ud) < 1:
                return True
            udhl = ud[0]
            if 1 + udhl > len(ud):
                return True
            udh = ud[1:1+udhl]
            seq = None
            total = None
            p = 0
            while p + 2 <= len(udh):
                iei = udh[p]; p += 1
                ielen = udh[p]; p += 1
                if p + ielen > len(udh): break
                ieval = udh[p:p+ielen]; p += ielen
                if iei == 0x00 and ielen == 3:
                    total = ieval[1]; seq = ieval[2]
                    break
                elif iei == 0x08 and ielen == 4:
                    total = ieval[2]; seq = ieval[3]
                    break
            if seq is not None and total is not None:
                if 1 <= seq <= total <= 255:
                    decision = (seq == total)
                    return decision
                else:
                    return True
            return True
        except Exception as e:
            self.log_error(f"Error analyzing MT-FSM parameters: {e}")
            self.log_info("MT-FSM decision: error path -> FINAL (send TCAP END)")
            return True
    def create_sri_sm_response(self, invoke_id, msisdn, orig_transaction_id):
        def _encode_oid(dotted: str) -> bytes:
            parts = [int(x) for x in dotted.split('.')]
            if len(parts) < 2:
                raise ValueError("OID must have at least two arcs")
            first = 40 * parts[0] + parts[1]
            out = [first]
            for arc in parts[2:]:
                if arc < 0x80:
                    out.append(arc)
                else:
                    stack = []
                    while arc > 0:
                        stack.insert(0, (arc & 0x7F) | 0x80)
                        arc >>= 7
                    stack[-1] &= 0x7F
                    out.extend(stack)
            return self.encode_asn1_tag_length(0x06, bytes(out))                    
        if not (0 <= invoke_id <= 255):
            self.log_error(f"Invalid invoke ID: {invoke_id}")
            invoke_id &= 0xFF
        imsi = self.generate_imsi(msisdn)
        nnn_gt = CONFIG['msc_gt']
        ton_npi = 0x91
        nnn_bcd = self.encode_bcd_digits(nnn_gt)
        nnn_address_string = bytes([ton_npi]) + nnn_bcd
        imsi_bcd = self.encode_bcd_digits(imsi)
        imsi_element = self.encode_asn1_tag_length(0x04, imsi_bcd)
        li_inner = (
            self.encode_asn1_tag_length(0x81, nnn_address_string)                         
        )
        location_info = self.encode_asn1_tag_length(0xa0, li_inner)                  
        result_param_content = imsi_element + location_info
        invoke_id_encoded = self.encode_asn1_tag_length(0x02, bytes([invoke_id]))
        op_code_local = self.encode_asn1_tag_length(0x02, bytes([45]))                      
        parameter_seq = self.encode_asn1_tag_length(0x30, result_param_content)                     
        result_seq = self.encode_asn1_tag_length(0x30, op_code_local + parameter_seq)
        rrl_content = invoke_id_encoded + result_seq
        component = self.encode_asn1_tag_length(0xA2, rrl_content)                       
        component_portion = self.encode_asn1_tag_length(0x6C, component)                    
        if orig_transaction_id and 1 <= len(orig_transaction_id) <= 4:
            dtid_value = orig_transaction_id
        else:
            dtid_value = struct.pack('!I', random.randint(0x10000000, 0xFFFFFFFF))
        dtid = self.encode_asn1_tag_length(0x49, dtid_value)
        dialogue_as_id_oid = _encode_oid("0.0.17.773.1.1.1")
        aare_pv = self.encode_asn1_tag_length(0x80, b"\x07\x80")
        acn_inner = _encode_oid("0.4.0.0.1.0.20.3")
        aare_acn = self.encode_asn1_tag_length(0xA1, acn_inner)
        aare_result = self.encode_asn1_tag_length(0xA2, b"\x02\x01\x00")
        rsd_inner = self.encode_asn1_tag_length(0xA1, b"\x02\x01\x00")
        aare_rsd = self.encode_asn1_tag_length(0xA3, rsd_inner)
        aare_payload = aare_pv + aare_acn + aare_result + aare_rsd
        aare = self.encode_asn1_tag_length(0x61, aare_payload)
        single_asn1 = self.encode_asn1_tag_length(0xA0, aare)
        external = self.encode_asn1_tag_length(0x28, dialogue_as_id_oid + single_asn1)
        dialogue_portion = self.encode_asn1_tag_length(0x6B, external)
        tcap_end_data = dtid + dialogue_portion + component_portion
        tcap_end = self.encode_asn1_tag_length(0x64, tcap_end_data)
        return tcap_end
    def decode_bcd_digits(self, bcd_data):
        try:
            digits = ""
            for i, byte in enumerate(bcd_data):
                d1 = byte & 0x0F
                d2 = (byte >> 4) & 0x0F
                if d1 != 15:
                    digits += str(d1)
                if d2 != 15:
                    digits += str(d2)
            return digits if digits else None
        except Exception as e:
            self.log_error(f"Error decoding BCD digits: {e}")
            return None
    def parse_sccp_addresses(self, sccp_data, offset):
        addresses = {'called': {}, 'calling': {}}
        try:
            if offset + 3 >= len(sccp_data):
                self.log_error("SCCP data too short for address parsing")
                return addresses, offset
            ptr_called = sccp_data[offset]
            ptr_calling = sccp_data[offset + 1]
            ptr_data = sccp_data[offset + 2]
            called_addr_start = offset + ptr_called
            if called_addr_start < len(sccp_data):
                called_addr_len = sccp_data[called_addr_start]
                if called_addr_start + called_addr_len < len(sccp_data):
                    called_addr_data = sccp_data[called_addr_start + 1:called_addr_start + 1 + called_addr_len]
                    addresses['called'] = self.parse_single_sccp_address(called_addr_data, "Called Party address")
            calling_addr_start = offset + ptr_calling + 1
            if calling_addr_start < len(sccp_data):
                calling_addr_len = sccp_data[calling_addr_start]
                if calling_addr_start + calling_addr_len < len(sccp_data):
                    calling_addr_data = sccp_data[calling_addr_start + 1 : calling_addr_start + 1 + calling_addr_len]
                    addresses['calling'] = self.parse_single_sccp_address(calling_addr_data, "Calling Party address")
            data_start = offset + ptr_data
            return addresses, data_start
        except Exception as e:
            self.log_error(f"Error parsing SCCP addresses: {e}")
            return addresses, offset
    def parse_single_sccp_address(self, addr_data, addr_type):
        address = {'gt': None, 'pc': None, 'ssn': None}
        try:
            if len(addr_data) < 1:
                self.log_error(f"{addr_type}: Empty address data")
                return address
            ai = addr_data[0]
            route_on_gt = (ai & 0x40) == 0
            gti = (ai >> 2) & 0x0F
            ssn_present = (ai & 0x02) != 0
            pc_present = (ai & 0x01) != 0
            offset = 1
            if pc_present:
                if offset + 2 <= len(addr_data):
                    pc = struct.unpack('<H', addr_data[offset:offset+2])[0]
                    address['pc'] = pc
                    offset += 2
            if ssn_present:
                if offset < len(addr_data):
                    ssn = addr_data[offset]
                    address['ssn'] = ssn
                    offset += 1
            if gti == 4 and offset < len(addr_data):
                gt_data = addr_data[offset:]
                if len(gt_data) >= 3:
                    tt = gt_data[0]
                    np_es = gt_data[1]
                    np = (np_es >> 4) & 0x0F
                    es = np_es & 0x0F
                    nai = gt_data[2]
                    digits_bcd = gt_data[3:]
                    digits = self.decode_bcd_digits(digits_bcd) or ''
                    address['gt'] = digits
        except Exception as e:
            self.log_error(f"Error parsing {addr_type}: {e}")
        return address
    def parse_tcap_message(self, tcap_data):
        def _read_len(buf, off):
            if off >= len(buf):
                return None
            first = buf[off]
            off += 1
            if first & 0x80:
                n = first & 0x7F
                if n == 0 or off + n > len(buf):
                    return None
                l = int.from_bytes(buf[off:off + n], 'big')
                return l, off + n                           
            else:
                return first, off                                   
        def _read_tlv(buf, off):
            if off >= len(buf):
                return None
            tag = buf[off]
            off += 1
            r = _read_len(buf, off)
            if r is None:
                return None
            length, val_start = r
            val_end = val_start + length
            if val_end > len(buf):
                return None
            next_off = val_end
            return tag, length, val_start, val_end, next_off
        def _decode_oid(oid_bytes):
            if not oid_bytes:
                return ""
            first = oid_bytes[0]
            arcs = [first // 40, first % 40]
            val = 0
            i = 1
            while i < len(oid_bytes):
                b = oid_bytes[i]
                val = (val << 7) | (b & 0x7F)
                if not (b & 0x80):
                    arcs.append(val)
                    val = 0
                i += 1
            return ".".join(str(x) for x in arcs)
        try:
            if len(tcap_data) < 2:
                self.log_error("Transaction Capabilities Application Part")
                self.log_error(" [Error: TCAP data too short]")
                return None, None, None, None, tcap_data
            top = _read_tlv(tcap_data, 0)
            if top is None:
                self.log_error("Invalid TCAP top-level TLV")
                return None, None, None, None, tcap_data
            tcap_tag, tcap_len, tcap_vs, tcap_ve, _ = top
            tcap_type = {0x62: 'begin', 0x64: 'end', 0x65: 'continue', 0x67: 'abort'}.get(tcap_tag, 'Unknown')
            transaction_id = None
            component_portion_slice = None
            off = tcap_vs
            while off < tcap_ve:
                node = _read_tlv(tcap_data, off)
                if node is None:
                    break
                tag, length, vs, ve, off = node
                if tag in (0x48, 0x49):                                         
                    transaction_id = tcap_data[vs:ve]
                elif tag == 0x6C:                    
                    component_portion_slice = (vs, ve)
            invoke_id = None
            op_code = None
            if component_portion_slice:
                cp_vs, cp_ve = component_portion_slice
                c_off = cp_vs
                while c_off < cp_ve:
                    comp = _read_tlv(tcap_data, c_off)
                    if comp is None:
                        break
                    c_tag, c_len, c_vs, c_ve, c_off = comp
                    if c_tag in (0xA1, 0xA2, 0xA3, 0xA4):
                        inner_off = c_vs
                        first = _read_tlv(tcap_data, inner_off)
                        if first:
                            f_tag, f_len, f_vs, f_ve, inner_off = first
                            if f_tag == 0x02:          
                                try:
                                    invoke_id = int.from_bytes(tcap_data[f_vs:f_ve], "big")
                                except Exception:
                                    pass
                        if c_tag == 0xA1:
                            scan = inner_off
                            while scan < c_ve and op_code is None:
                                tlv = _read_tlv(tcap_data, scan)
                                if tlv is None:
                                    break
                                s_tag, s_len, s_vs, s_ve, scan = tlv
                                if s_tag == 0x80:
                                    op_code = int.from_bytes(tcap_data[s_vs:s_ve], "big")
                                elif s_tag == 0x06:
                                    op_code = ('oid', _decode_oid(tcap_data[s_vs:s_ve]))
                                elif s_tag == 0xA1:
                                    inner2 = _read_tlv(tcap_data, s_vs)
                                    if inner2 and inner2[0] == 0x06:
                                        _, _, i_vs, i_ve, _ = inner2
                                        op_code = ('oid', _decode_oid(tcap_data[i_vs:i_ve]))
                                elif s_tag == 0xA0:
                                    inner2 = _read_tlv(tcap_data, s_vs)
                                    if inner2 and inner2[0] in (0x80, 0x02):
                                        _, _, i_vs, i_ve, _ = inner2
                                        op_code = int.from_bytes(tcap_data[i_vs:i_ve], "big")
                                elif s_tag == 0x02 and s_len <= 2 and op_code is None:
                                    val = int.from_bytes(tcap_data[s_vs:s_ve], "big")
                                    if 1 <= val <= 255:
                                        op_code = val
                        elif c_tag == 0xA2:
                            res = _read_tlv(tcap_data, inner_off)
                            if res and res[0] == 0x30:           
                                _, _, r_vs, r_ve, _ = res
                                r_off = r_vs
                                op = _read_tlv(tcap_data, r_off)
                                if op:
                                    o_tag, o_len, o_vs, o_ve, _ = op
                                    if o_tag == 0x80:
                                        op_code = int.from_bytes(tcap_data[o_vs:o_ve], "big")
                                    elif o_tag == 0xA0:
                                        inner3 = _read_tlv(tcap_data, o_vs)
                                        if inner3:
                                            i_tag, _, i_vs, i_ve, _ = inner3
                                            if i_tag in (0x80, 0x02):
                                                op_code = int.from_bytes(tcap_data[i_vs:i_ve], "big")
                                    elif o_tag == 0x02:
                                        op_code = int.from_bytes(tcap_data[o_vs:o_ve], "big")
                                    elif o_tag == 0x06:
                                        op_code = ('oid', _decode_oid(tcap_data[o_vs:o_ve]))
                                    elif o_tag == 0xA1:
                                        inner4 = _read_tlv(tcap_data, o_vs)
                                        if inner4 and inner4[0] == 0x06:
                                            _, _, i_vs, i_ve, _ = inner4
                                            op_code = ('oid', _decode_oid(tcap_data[i_vs:i_ve]))
                        break
            msisdn = self.extract_msisdn_from_tcap(tcap_data)
            return transaction_id, invoke_id, op_code, msisdn, tcap_data
        except Exception as e:
            self.log_error(f"Error parsing TCAP message (op_code extraction): {e}")
            return None, None, None, None, tcap_data
    def extract_msisdn_from_tcap(self, tcap_data):
        msisdn = None
        for i in range(len(tcap_data) - 5):
            if tcap_data[i] in [0x04, 0x80, 0x81, 0x82]:
                length = tcap_data[i + 1]
                if 3 <= length <= 15:
                    if i + 2 + length <= len(tcap_data):
                        potential_data = tcap_data[i + 2:i + 2 + length]
                        if len(potential_data) > 0 and potential_data[0] == 0x91:
                            msisdn_bcd = potential_data[1:]
                            msisdn = self.decode_bcd_digits(msisdn_bcd)
                            if msisdn and len(msisdn) >= 8:
                                return msisdn
        if not msisdn:
            pass
        return msisdn
    def create_sccp_response(self, calling_addr, called_addr, tcap_data):
        try:
            sccp_type = SCCP_XUDT
            protocol_class = 0x80
            hop_counter = 0x0F
            response_called = SCCPAddress(
                gt=calling_addr.get('gt') or CONFIG.get('remote_gt'),
                ssn=8
            )
            response_calling = SCCPAddress(
                gt=CONFIG['hlr_gt'],
                ssn=6
            )
            called_addr_data = response_called.pack()
            calling_addr_data = response_calling.pack()
            if len(called_addr_data) == 0 or len(calling_addr_data) == 0:
                self.log_error("Empty SCCP address encoding detected")
                return None
            assert called_addr_data[0] + 1 == len(called_addr_data), "Called length mismatch"
            assert calling_addr_data[0] + 1 == len(calling_addr_data), "Calling length mismatch"
            ptr1 = 4
            ptr2 = ptr1 + called_addr_data[0]
            ptr3 = ptr2 + calling_addr_data[0]
            ptr4 = 0
            sccp_header = struct.pack('!BBBBBBB', sccp_type, protocol_class, hop_counter, ptr1, ptr2, ptr3, ptr4)
            data_len = len(tcap_data)
            sccp_data = (
                sccp_header +
                called_addr_data +
                calling_addr_data +
                struct.pack('!B', data_len) +                                 
                tcap_data                               
            )
            return sccp_data
        except Exception as e:
            self.log_error(f"Error creating SCCP response: {e}")
            return None
    def create_m3ua_data_message(self, dest_pc, orig_pc, sccp_data, si=None, ni=None, mp=0, sls=None):
        try:
            si = 3 if si is None else si
            ni = CONFIG['network_indicator'] if ni is None else ni
            sls = 0 if sls is None else sls
            pd_header = struct.pack('!I', orig_pc) + struct.pack('!I', dest_pc) + bytes([si, ni, mp, sls])
            protocol_data = pd_header + sccp_data
            params = []
            if CONFIG.get('route_context') is not None:
                params.append(M3UAParameter(M3UA_PARAM_ROUTING_CONTEXT,
                                           struct.pack('!I', CONFIG['route_context'])))
            params.append(M3UAParameter(M3UA_PARAM_PROTOCOL_DATA, protocol_data))
            param_data = b''.join([p.pack() for p in params])
            msg_length = 8 + len(param_data)
            m3ua_msg = M3UAMessage(version=1, msg_class=M3UA_TRANSFER_CLASS,
                                 msg_type=M3UA_DATA, length=msg_length,
                                 data=param_data)
            return m3ua_msg
        except Exception as e:
            self.log_error(f"Error creating M3UA DATA message: {e}")
            return None
    def parse_and_log_response(self, response_data, msg_type):
        try:
            if len(response_data) < 8:
                self.log_error("MTP 3 User Adaptation Layer")
                self.log_error("    [Error: Message too short for M3UA header]")
                return
            version, reserved, msg_class, msg_type_val, msg_length = struct.unpack('!BBBBI', response_data[:8])
            msg_class_name = {
                M3UA_TRANSFER_CLASS: 'Transfer messages',
                M3UA_ASPSM_CLASS: 'ASP State Maintenance messages',
                M3UA_ASPTM_CLASS: 'ASP Traffic Maintenance messages',
                M3UA_MGMT_CLASS: 'Management messages'
            }.get(msg_class, f'Unknown ({msg_class})')
            msg_type_name = {
                M3UA_DATA: 'Payload data (DATA)',
                M3UA_ASPUP: 'ASP Up',
                M3UA_ASPUP_ACK: 'ASP Up Ack',
                M3UA_ASPAC: 'ASP Active',
                M3UA_ASPAC_ACK: 'ASP Active Ack'
            }.get(msg_type_val, f'Unknown ({msg_type_val})')
            offset = 8
            param_num = 1
            while offset < len(response_data):
                if offset + 4 > len(response_data):
                    self.log_error("    [Error: Incomplete parameter at offset {offset}]")
                    break
                tag, length = struct.unpack('!HH', response_data[offset:offset+4])
                param_data = response_data[offset+4:offset+length] if length > 4 else b''
                param_name = self.get_m3ua_param_name(tag)
                if tag == M3UA_PARAM_ROUTING_CONTEXT:
                    if len(param_data) >= 4:
                        rc_value = struct.unpack('!I', param_data[:4])[0]
                elif tag == M3UA_PARAM_PROTOCOL_DATA:
                    self.parse_protocol_data_response(param_data)
                padded_length = (length + 3) & ~3
                offset += padded_length
                param_num += 1
        except Exception as e:
            self.log_error(f"Error parsing {msg_type}: {e}")
    def parse_protocol_data_response(self, protocol_data):
        try:
            if len(protocol_data) < 12:
                self.log_error("    Protocol data")
                self.log_error("        [Error: Protocol Data too short]")
                return
            opc = struct.unpack('!I', protocol_data[0:4])[0]
            dpc = struct.unpack('!I', protocol_data[4:8])[0]
            si = protocol_data[8]
            ni = protocol_data[9]
            mp = protocol_data[10]
            sls = protocol_data[11]
            if len(protocol_data) > 12:
                sccp_data = protocol_data[12:]
                self.parse_sccp_response(sccp_data, "SCCP Data")
        except Exception as e:
            self.log_error(f"Error parsing protocol data: {e}")
    def parse_sccp_response(self, sccp_data, context):
        try:
            if len(sccp_data) < 5:
                self.log_error(f"Signalling Connection Control Part")
                self.log_error(f"    [Error: SCCP data too short]")
                return
            sccp_type = sccp_data[0]
            protocol_class = sccp_data[1]
            hop_counter = sccp_data[2]
            ptr1 = sccp_data[3]
            ptr2 = sccp_data[4]
            ptr3 = sccp_data[5]
            ptr4 = sccp_data[6]
            sccp_type_name = {
                SCCP_UDT: 'Unitdata',
                SCCP_XUDT: 'Extended Unitdata',
                SCCP_UDTS: 'Unitdata Service'
            }.get(sccp_type, f'Unknown (0x{sccp_type:02X})')
            addresses, tcap_offset = self.parse_sccp_addresses(sccp_data, 3)
            if tcap_offset < len(sccp_data):
                tcap_data = sccp_data[tcap_offset+3:]
                self.parse_tcap_response(tcap_data)
        except Exception as e:
            self.log_error(f"Error parsing {context}: {e}")
    def parse_tcap_response(self, tcap_data):
        try:
            if len(tcap_data) < 2:
                self.log_error("Transaction Capabilities Application Part")
                self.log_error("    [Error: TCAP data too short]")
                return
            tcap_tag = tcap_data[0]
            tcap_len = tcap_data[1]
            tcap_type = {TCAP_BEGIN: 'begin', TCAP_END: 'end', TCAP_CONTINUE: 'continue', TCAP_ABORT: 'abort'}.get(tcap_tag, 'Unknown')
            transaction_id = None
            for i in range(len(tcap_data) - 4):
                if tcap_data[i] == 0x49:               
                    tid_len = tcap_data[i + 1]
                    if tid_len <= 4 and i + 2 + tid_len <= len(tcap_data):
                        transaction_id = tcap_data[i + 2:i + 2 + tid_len]
                        break
            offset = 2
            while offset < len(tcap_data):
                if tcap_data[offset] == 0xA2:                   
                    comp_len = tcap_data[offset + 1]
                    if offset + 2 + comp_len <= len(tcap_data):
                        comp_data = tcap_data[offset + 2:offset + 2 + comp_len]
                    break
                offset += 1
        except Exception as e:
            self.log_error(f"Error parsing TCAP response: {e}")
    def parse_map_sri_sm_response(self, param_data):
        try:
            offset = 0
            while offset < len(param_data):
                tag = param_data[offset]
                length = param_data[offset + 1]
                value = param_data[offset + 2:offset + 2 + length]
                if tag == ASN1_OCTET_STRING:
                    digits = self.decode_bcd_digits(value)
                elif tag == 0xA1:
                    inner_offset = 0
                    while inner_offset < len(value):
                        inner_tag = value[inner_offset]
                        inner_len = value[inner_offset + 1]
                        inner_value = value[inner_offset + 2:inner_offset + 2 + inner_len]
                        if inner_tag == ASN1_CONTEXT_0 and inner_value[0] == 0x91:
                            digits = self.decode_bcd_digits(inner_value[1:])
                        elif inner_tag == ASN1_CONTEXT_1:
                            lmsi = struct.unpack('!I', inner_value)[0]
                        inner_offset += 2 + inner_len
                offset += 2 + length
        except Exception as e:
            self.log_error(f"Error parsing MAP SRI-SM response: {e}")
    def parse_m3ua_data(self, m3ua_msg, conn, addr):
        try:            
            self.log_info(f"Incoming M3UA DATA from {addr[0]}:{addr[1]}")
            raw = m3ua_msg.pack()
            if len(raw) < 8:
                self.log_error("MTP 3 User Adaptation Layer")
                self.log_error("    [Error: Message too short for M3UA header]")
                return
            version, reserved, msg_class, msg_type, msg_length = struct.unpack('!BBBBI', raw[:8])
            msg_class_name = {M3UA_TRANSFER_CLASS: 'Transfer messages'}.get(msg_class, f'Unknown ({msg_class})')
            msg_type_name = {M3UA_DATA: 'Payload data (DATA)'}.get(msg_type, f'Unknown ({msg_type})')
            offset = 8
            protocol_data = None
            routing_context = None
            while offset < len(raw):
                tag, length = struct.unpack('!HH', raw[offset:offset+4])
                param_data = raw[offset+4:offset+length] if length > 4 else b''
                param_name = self.get_m3ua_param_name(tag)
                if tag == M3UA_PARAM_ROUTING_CONTEXT:
                    if len(param_data) >= 4:
                        routing_context = struct.unpack('!I', param_data[:4])[0]
                elif tag == M3UA_PARAM_PROTOCOL_DATA:
                    protocol_data = param_data
                padded_length = (length + 3) & ~3
                offset += padded_length
            if not protocol_data:
                self.log_error("    [Error: No Protocol Data found in M3UA message]")
                return
        except Exception as e:
            self.log_error(f"Error in parse_m3ua_data: {e}")
            import traceback
            self.log_error(f"Traceback: {traceback.format_exc()}")
        finally:
            pass
    def get_m3ua_param_name(self, tag):
        param_names = {
            0x0001: "Error Code",
            0x0006: "Routing Context",
            0x0210: "Protocol Data",
            0x0200: "Network Appearance",
            0x0013: "Correlation ID",
            0x0004: "Info String",
            0x000b: "Traffic Mode Type",
            0x0011: "ASP Identifier"
        }
        return param_names.get(tag, f"Unknown (0x{tag:04X})")
    def handle_m3ua_message(self, message, conn, addr):
        conn_key = f"{addr[0]}:{addr[1]}"
        if conn_key not in self.asp_states:
            self.asp_states[conn_key] = {'state': 'ASP-DOWN'}
        asp_state = self.asp_states[conn_key]
        if message.msg_class == M3UA_ASPSM_CLASS:
            if message.msg_type == M3UA_ASPUP:
                self.log_info(f"M3UA ASPUP received from {addr[0]}:{addr[1]}")
                response = self.create_m3ua_response(M3UA_ASPSM_CLASS, M3UA_ASPUP)
                if response:
                    conn.send(response.pack())
                    asp_state['state'] = 'ASP-INACTIVE'
                    self.log_info(f"M3UA ASPUP-ACK sent to {addr[0]}:{addr[1]}")
            elif message.msg_type == M3UA_BEAT:
                response = self.create_m3ua_response(M3UA_ASPSM_CLASS, M3UA_BEAT)
                if response:
                    conn.send(response.pack())
        elif message.msg_class == M3UA_ASPTM_CLASS:
            if message.msg_type == M3UA_ASPAC:
                self.log_info(f"M3UA ASPAC received from {addr[0]}:{addr[1]}")
                response = self.create_m3ua_response(M3UA_ASPTM_CLASS, M3UA_ASPAC)
                if response:
                    conn.send(response.pack())
                    asp_state['state'] = 'ASP-ACTIVE'
                    self.log_info(f"M3UA ASPAC-ACK sent to {addr[0]}:{addr[1]}")
        elif message.msg_class == M3UA_TRANSFER_CLASS:
            if message.msg_type == M3UA_DATA:
                self.log_info(f"M3UA DATA received from {addr[0]}:{addr[1]} ")
                self.parse_m3ua_data(message, conn, addr)
                self.handle_m3ua_data(message, conn, addr)
                self.log_info(f"M3UA DATA-ACK sent to {addr[0]}:{addr[1]}")
    def handle_m3ua_data(self, m3ua_msg, conn, addr):
        try:
            offset = 8
            protocol_data = None
            routing_context = None
            while offset < len(m3ua_msg.data):
                param, param_len = M3UAParameter.unpack(m3ua_msg.data[offset:])
                if not param or param_len == 0:
                    break
                if param.tag == M3UA_PARAM_PROTOCOL_DATA:
                    protocol_data = param.value
                elif param.tag == M3UA_PARAM_ROUTING_CONTEXT:
                    routing_context = struct.unpack('!I', param.value)[0]
                offset += param_len
            if not protocol_data:
                self.log_error("No Protocol Data found in M3UA message")
                return
            if len(protocol_data) < 12:
                self.log_error("Protocol Data too short for MTP3 header")
                return
            opc = struct.unpack('!I', protocol_data[0:4])[0]
            dpc = struct.unpack('!I', protocol_data[4:8])[0]
            si = protocol_data[8]
            ni = protocol_data[9]
            mp = protocol_data[10]
            sls = protocol_data[11]
            sccp_data = protocol_data[12:]
            if len(sccp_data) == 0:
                self.log_error("No SCCP data found after MTP3 header")
                return
            sccp_type = sccp_data[0]
            if sccp_type in [SCCP_UDT, SCCP_XUDT]:
                self.handle_sccp_udt(sccp_data, opc, dpc, conn, addr)
            else:
                self.log_error(f"Unsupported SCCP message type: 0x{sccp_type:02X}")
        except Exception as e:
            self.log_error(f"Error in handle_m3ua_data: {e}")
            import traceback
            self.log_error(f"Traceback: {traceback.format_exc()}")
    def create_tcap_continue_response(self, orig_transaction_id):
        try:
            new_otid = struct.pack('!I', random.randint(0x10000000, 0xFFFFFFFF))                    
            otid = self.encode_asn1_tag_length(0x48, new_otid)                         
            dtid = self.encode_asn1_tag_length(0x49, orig_transaction_id)                               
            dialogue_portion = self._build_tcap_dialogue_portion_aare("0.4.0.0.1.0.25.3")                             
            tcap_continue_data = otid + dtid + dialogue_portion
            tcap_continue = self.encode_asn1_tag_length(0x65, tcap_continue_data)              
            return tcap_continue
        except Exception as e:
            self.log_error(f"Error creating TCAP CONTINUE response: {e}")
            return None
    def handle_sccp_udt(self, sccp_data, orig_pc, dest_pc, conn, addr):
        try:
            if len(sccp_data) < 5:
                self.log_error("SCCP UDT data too short")
                return
            protocol_class = sccp_data[1]
            addresses, tcap_offset = self.parse_sccp_addresses(sccp_data, 3)
            if tcap_offset < len(sccp_data):
                tcap_data = sccp_data[tcap_offset+3:]
                if tcap_data and tcap_data[0] == TCAP_CONTINUE:
                   self._on_dialogue_continue(tcap_data)
                if tcap_data and tcap_data[0] == TCAP_END:
                  self._on_dialogue_end_progress(tcap_data)
                transaction_id, invoke_id, op_code, msisdn, _ = self.parse_tcap_message(tcap_data)
                sccp_response = None
                if invoke_id is not None and isinstance(op_code, int):
                    if op_code == MAP_SRI_SM and msisdn:
                      op_code_description = "sendRoutingInfoForSM"
                      self.log_info(f"Incoming request : {op_code_description}  ")
                      response_tcap = self.create_sri_sm_response(invoke_id, msisdn, transaction_id)
                      sccp_response = self.create_sccp_response(addresses['calling'], addresses['called'], response_tcap)
                    elif op_code == MAP_MT_FSM:
                      op_code_description = "mt-forwardSM"
                      self.log_info(f"Incoming request : {op_code_description}  ")
                      response_tcap = self.create_mt_fsm_response(invoke_id, op_code, transaction_id,tcap_data)
                      sccp_response = self.create_sccp_response(addresses['calling'], addresses['called'], response_tcap)
                    elif op_code == MAP_MO_FSM:
                      op_code_description = "mo-forwardSM"
                      self.log_info(f"Incoming request : {op_code_description}  ")
                      self.log_info("mo-forwardSM (ReturnResultLast) – TCAP END received; no action required.")
                    else:
                      sccp_response = None
                    if sccp_response:
                        m3ua_response = self.create_m3ua_data_message(
                            orig_pc, dest_pc, sccp_response, si=3, ni=CONFIG['network_indicator'], mp=0, sls=0
                        )
                        if m3ua_response:
                            response_data = m3ua_response.pack()
                            try:
                                bytes_sent = conn.send(response_data)
                                if bytes_sent == len(response_data):
                                    self.log_info(f"{CONFIG['local_pc']} → {CONFIG['remote_pc']} Send GSM MAP 232 SACK returnResultLast {op_code_description}")
                                else:
                                    self.log_error(f"✗ Partial send: {bytes_sent}/{len(response_data)} bytes")
                            except Exception as e:
                                self.log_error(f"✗ Failed to send response: {e}")
                        else:
                            self.log_error("Failed to create M3UA response")
                    else:
                        self.log_error("sccp_response = None , Not attempt to send anything ")
                elif transaction_id is not None:                                
                    tcap_tag = tcap_data[0] if len(tcap_data) > 0 else None
                    if tcap_tag == TCAP_BEGIN:                               
                        self.log_info("Incoming request: TCAP BEGIN (dialogue establishment)")                        
                        response_tcap = self.create_tcap_continue_response(transaction_id)
                        if response_tcap:
                            sccp_response = self.create_sccp_response(addresses['calling'], addresses['called'], response_tcap)
                            if sccp_response:
                                m3ua_response = self.create_m3ua_data_message(
                                    orig_pc, dest_pc, sccp_response, si=3, ni=CONFIG['network_indicator'], mp=0, sls=0
                                )
                                if m3ua_response:
                                    response_data = m3ua_response.pack()
                                    try:
                                        bytes_sent = conn.send(response_data)
                                        if bytes_sent == len(response_data):
                                            self.log_info(f"{CONFIG['local_pc']} → {CONFIG['remote_pc']} TCAP CONTINUE (DTID = OTID)")
                                        else:
                                            self.log_error(f"✗ Partial send: {bytes_sent}/{len(response_data)} bytes")
                                    except Exception as e:
                                        self.log_error(f"✗ Failed to send TCAP CONTINUE: {e}")
                                else:
                                    self.log_error("Failed to create M3UA response for TCAP CONTINUE")
                            else:
                                self.log_error("Failed to create SCCP response for TCAP CONTINUE")
                        else:
                            self.log_error("Failed to create TCAP CONTINUE response")
                    elif tcap_tag == TCAP_ABORT:                                     
                        self.log_info("Received TCAP ABORT - no response required")
                    elif tcap_tag == TCAP_END:                                   
                        self.log_info("Received TCAP END - no response required")
                    else:
                        self.log_info(f"Received TCAP message type 0x{tcap_tag:02x} - no response generated")
                else:
                    self.log_error("Could not extract invoke_id or transaction_id from TCAP message")
            else:
                self.log_error("No TCAP data found in SCCP UDT")
        except Exception as e:
            self.log_error(f"Error handling SCCP UDT: {e}")
    def handle_client(self, conn, addr):
        try:
            self.log_info(f"SCTP association established with {addr[0]}:{addr[1]}")
            while self.running:
                try:
                    data = conn.recv(4096)
                    if not data:
                        self.log_info(f"Client {addr[0]}:{addr[1]} disconnected")
                        break
                    m3ua_msg = M3UAMessage.unpack(data)
                    if m3ua_msg and m3ua_msg.version == 1:
                        self.handle_m3ua_message(m3ua_msg, conn, addr)
                    else:
                        self.log_error(f"Invalid M3UA message from {addr[0]}:{addr[1]}")
                except socket.timeout:
                    continue
                except socket.error as e:
                    self.log_error(f"Socket error from {addr[0]}:{addr[1]}: {e}")
                    break
                except Exception as e:
                    self.log_error(f"Unexpected error handling data from {addr[0]}:{addr[1]}: {e}")
                    break
        except Exception as e:
            self.log_error(f"Error in client handler for {addr[0]}:{addr[1]}: {e}")
        finally:
            conn_key = f"{addr[0]}:{addr[1]}"
            if conn_key in self.asp_states:
                del self.asp_states[conn_key]
            try:
                conn.close()
            except:
                pass
            self.log_info(f"Connection closed with {addr[0]}:{addr[1]}")
    def _pick_active_conn(self):
        try:
            for key, info in self.asp_states.items():
                if info.get('state') == 'ASP-ACTIVE' and info.get('conn'):
                    return info['conn'], info.get('addr')
            for key, info in self.asp_states.items():
                if info.get('conn'):
                    return info['conn'], info.get('addr')
            return None, None
        except Exception as e:
            self.log_error(f"_pick_active_conn error: {e}")
            return None, None
    def _send_sccp_tcap_on_active(self, tcap_data: bytes, called_gt: str, calling_gt: str) -> bool:
        conn, addr = self._pick_active_conn()
        if not conn:
            self.log_error("No ASP-ACTIVE association available. Wait for peer ASPUP/ASPAC.")
            return False
        if not called_gt:
            self.log_error("Missing called_gt (destination GT). Set CONFIG['remote_gt'] or provide --smsc.")
            return False
        if not calling_gt:
            self.log_error("Missing calling_gt (origin GT). Set CONFIG['msc_gt'] / ['hlr_gt'] / ['local_gt'].")
            return False
        called_ssn = int(CONFIG.get('called_ssn', 8))
        calling_ssn = int(CONFIG.get('calling_ssn', 8))
        try:
            called = SCCPAddress(gt=called_gt, ssn=called_ssn)
            calling = SCCPAddress(gt=calling_gt, ssn=calling_ssn)
            sccp_pdu = self.create_sccp_response(calling.__dict__, called.__dict__, tcap_data)
            if not sccp_pdu:
                self.log_error("Failed to build SCCP PDU for MO-FSM.")
                return False
        except Exception as e:
            self.log_error(f"SCCP build error: {e}")
            return False
        try:
            m3ua_msg = self.create_m3ua_data_message(
                dest_pc=CONFIG['remote_pc'],
                orig_pc=CONFIG['local_pc'],
                sccp_data=sccp_pdu,
                si=3,       
                ni=CONFIG.get('network_indicator', 2),
                mp=0,
                sls=0
            )
            if not m3ua_msg:
                self.log_error("Failed to construct M3UA DATA message.")
                return False
            raw = m3ua_msg.pack()
        except Exception as e:
            self.log_error(f"M3UA build error: {e}")
            return False
        try:
            conn.sendall(raw)
            self.log_info(f"{CONFIG['local_pc']} → {CONFIG['remote_pc']} M3UA DATA (SCCP + TCAP) sent")
            return True
        except Exception as e:
            self.log_error(f"Send error on active association {addr[0]}:{addr[1]}: {e}")
            return False
    def _tcap_continue_with_component(self, our_otid: bytes, peer_otid: bytes, component: bytes) -> bytes:
        body = self.encode_asn1_tag_length(0x48, our_otid) +\
               self.encode_asn1_tag_length(0x49, peer_otid) +\
               component
        return self.encode_asn1_tag_length(0x65, body)
    def _tcap_end_with_component(self, peer_otid: bytes, component: bytes) -> bytes:
        body = self.encode_asn1_tag_length(0x49, peer_otid) + component
        return self.encode_asn1_tag_length(0x64, body)
    def _make_concat_udh_8bit(self, ref: int, total: int, seq: int) -> bytes:
        return bytes([0x00, 0x03, ref & 0xFF, total & 0xFF, seq & 0xFF])
    def _plan_mo_segments(self, oa: str, da: str, text: str, smsc: str):
        smsc = smsc or CONFIG.get('smsc_gt') or CONFIG.get('remote_gt')
        if not smsc:
            raise ValueError("No SMSC address configured. Pass --smsc TON.NPI.DIGITS "
                             "or set CONFIG['smsc_gt']/CONFIG['remote_gt'].")
        def parse_addr(s: str):
            parts = str(s).split('.')
            if len(parts) >= 3:
                ton = int(parts[0]); npi = int(parts[1])
                digits = ''.join(ch for ch in ''.join(parts[2:]) if ch.isdigit())
                return ton, npi, digits
            return 1, 1, ''
        oa_ton, oa_npi, oa_digits = parse_addr(oa)
        da_ton, da_npi, da_digits = parse_addr(da)
        smsc_ton, smsc_npi, smsc_digits = parse_addr(smsc)
        def _split_segments(msg: str):
            if any(ord(ch) > 0x7F for ch in msg):
                per = 67
                return [{'enc': 'ucs2', 'text': msg[i:i+per]} for i in range(0, len(msg), per)]
            res = []
            i = 0
            ext = set('^{}\\[]~]|€')
            while i < len(msg):
                used = 0
                j = i
                while j < len(msg):
                    add = 2 if msg[j] in ext else 1
                    if used + add > 153:
                        break
                    used += add
                    j += 1
                res.append({'enc': 'gsm7', 'text': msg[i:j]})
                i = j
            return res
        segs = _split_segments(text)
        total = len(segs)
        ref = random.randint(0, 255)
        comps = []
        base_mr = random.randint(0, 255)        
        for idx, seg in enumerate(segs, start=1):            
            udh = self._make_concat_udh_8bit(ref, total, idx)
            if seg['enc'] == 'ucs2':
                FO = 0x01 | 0x40                
                MR = (base_mr + (idx - 1)) & 0xFF
                digits = ''.join(ch for ch in da_digits if ch.isdigit())
                da_len = len(digits)
                TOA = 0x80 | ((da_ton & 7) << 4) | (da_npi & 0x0F)
                DA = bytes([da_len, TOA]) + self.encode_bcd_digits(digits)
                PID = 0x00
                DCS = 0x08       
                UD = bytes([len(udh)]) + udh + seg['text'].encode('utf-16-be')
                UDL = len(UD)
                tpdu = bytes([FO, MR]) + DA + bytes([PID, DCS, UDL]) + UD
            else:
                FO = 0x01 | 0x40                
                MR = (base_mr + (idx - 1)) & 0xFF
                digits = ''.join(ch for ch in da_digits if ch.isdigit())
                da_len = len(digits)
                TOA = 0x80 | ((da_ton & 7) << 4) | (da_npi & 0x0F)
                DA = bytes([da_len, TOA]) + self.encode_bcd_digits(digits)
                PID = 0x00
                DCS = 0x00       
                UD, UDL = self._gsm7_pack_with_udh(udh, seg['text'])
                tpdu = bytes([FO, MR]) + DA + bytes([PID, DCS, UDL]) + UD
            rpdu = tpdu
            _indent = ' ' * 8
            mt = rpdu[0] & 0x3F                                              
            has_rp_user = (0x04 in rpdu[:48]) 
            comps.append(self._build_mo_fsm_component_from_rpdu(
                oa_ton, oa_npi, oa_digits, smsc_ton, smsc_npi, smsc_digits, rpdu))
        begin, our_otid = self.create_tcap_begin_dialogue_only("0.4.0.0.1.0.21.3")             
        return begin, our_otid, comps
    def _build_mo_fsm_component_from_rpdu(
        self,
        oa_ton: int, oa_npi: int, oa_digits: str,
        smsc_ton: int, smsc_npi: int, smsc_digits: str,
        rpdu: bytes
    ) -> bytes:
        def _addr(ton: int, npi: int, digits: str) -> bytes:
            digits_only = ''.join(ch for ch in digits if ch.isdigit())
            toa = 0x80 | ((ton & 0x07) << 4) | (npi & 0x0F)
            return bytes([toa]) + self.encode_bcd_digits(digits_only)
        sm_rp_da = self.encode_asn1_tag_length(0x84, _addr(smsc_ton, smsc_npi, smsc_digits))      
        sm_rp_oa = self.encode_asn1_tag_length(0x82, _addr(oa_ton, oa_npi, oa_digits))      
        sm_rp_ui = self.encode_asn1_tag_length(0x04, rpdu)               
        param_seq = self.encode_asn1_tag_length(0x30, sm_rp_da + sm_rp_oa + sm_rp_ui)
        invoke_id_enc = self.encode_asn1_tag_length(0x02, bytes([random.randint(1, 127)]))
        invoke_id_enc = self.encode_asn1_tag_length(0x02, bytes([0]))
        opcode_local = self.encode_asn1_tag_length(0x02, bytes([46]))               
        invoke = self.encode_asn1_tag_length(0xA1, invoke_id_enc + opcode_local + param_seq)
        return self.encode_asn1_tag_length(0x6C, invoke)                    
    def _build_mo_fsm_component(self, oa_ton:int, oa_npi:int, oa_digits:str,
                                smsc_ton:int, smsc_npi:int, smsc_digits:str,
                                tpdu: bytes) -> bytes:
        def _addr(ton,npi,digits) -> bytes:
            toa = 0x80 | ((ton & 7) << 4) | (npi & 0x0F)
            return bytes([toa]) + self.encode_bcd_digits(''.join(ch for ch in digits if ch.isdigit()))
        sm_rp_da = self.encode_asn1_tag_length(0x84, _addr(smsc_ton, smsc_npi, smsc_digits))
        sm_rp_oa = self.encode_asn1_tag_length(0x82, _addr(oa_ton, oa_npi, oa_digits))
        rpdu = self._build_rp_mo_data(smsc_ton, smsc_npi, smsc_digits, tpdu)
        sm_rp_ui = self.encode_asn1_tag_length(0x04, rpdu)
        param_seq = self.encode_asn1_tag_length(0x30, sm_rp_da + sm_rp_oa + sm_rp_ui)
        invoke_id_enc = self.encode_asn1_tag_length(0x02, bytes([random.randint(1,127)]))
        opcode_local = self.encode_asn1_tag_length(0x02, bytes([46]))               
        invoke = self.encode_asn1_tag_length(0xA1, invoke_id_enc + opcode_local + param_seq)
        return self.encode_asn1_tag_length(0x6C, invoke)                    
    def create_mo_fsm_invoke(self, oa_str: str, da_str: str, text: str, smsc_str: str = None) -> bytes:
        def _digits_only(s: str) -> str:
            return ''.join(ch for ch in s if ch.isdigit())
        def _parse_ton_npi_digits(s: str):
            parts = s.split('.')
            if len(parts) >= 3:
                ton = int(parts[0]); npi = int(parts[1]); digits = _digits_only(''.join(parts[2:]))
            else:
                ton, npi, digits = 1, 1, _digits_only(s)
            return ton, npi, digits
        def _ensure_digits(label: str, digits: str):
            if not digits:
                raise ValueError(f"{label} has no digits after sanitization; TP-DA/TP-OA cannot be empty.")
        def _build_address_string(ton: int, npi: int, digits: str) -> bytes:
            toa = 0x80 | ((ton & 0x07) << 4) | (npi & 0x0F)
            return bytes([toa]) + self.encode_bcd_digits(digits)
        def _gsm7_pack(text: str) -> bytes:
                septets = [ord(c) & 0x7F for c in text]
                out = bytearray()
                acc = 0
                bits = 0
                for s in septets:
                    acc |= (s << bits)                                                  
                    bits += 7
                    while bits >= 8:
                        out.append(acc & 0xFF)
                        acc >>= 8
                        bits -= 8
                if bits > 0:
                    out.append(acc & 0xFF)
                return bytes(out)
        def _gsm7_septet_len(s: str) -> int:
            ext = set('^{}\\[~]|€')
            length = 0
            for ch in s:
                length += 2 if ch in ext else 1
            return length
        def _needs_ucs2(s: str) -> bool:
          return any(ord(ch) > 0x7F for ch in s)
        def _build_sms_submit_tpdu(da_ton, da_npi, da_digits, text) -> bytes:
            FO = 0x01
            MR = random.randint(0, 255)
            da_digits = _digits_only(da_digits)
            _ensure_digits("TP-DA", da_digits)
            da_len = len(da_digits)                                
            TOA = 0x80 | ((da_ton & 7) << 4) | (da_npi & 0x0F)                             
            da_tbcd = self.encode_bcd_digits(da_digits)                           
            DA = bytes([da_len, TOA]) + da_tbcd
            PID = 0x00          
            DCS = 0x00                      
            UD = _gsm7_pack(text)
            UDL = _gsm7_septet_len(text)                          
            return bytes([FO, MR]) + DA + bytes([PID, DCS, UDL]) + UD
        def _build_rp_mo_data(da_ton: str,da_npi: str,da_digits: str, tpdu: bytes,text) -> bytes:
            rp_mti = 0x01               
            rp_mr = random.randint(0, 255)
            TOA = 0x80 | ((da_ton & 7) << 4) | (da_npi & 0x0F)                             
            da_tbcd = self.encode_bcd_digits(da_digits)                           
            da_len = len(da_digits)
            rp_da_ie = bytes([da_len, TOA]) + da_tbcd
            PID = 0x00          
            if _needs_ucs2(text):
                DCS = 0x08       
                UD = text.encode('utf-16-be')
                if len(UD) > 140:
                    self.log_error(f"[MO-FSM] UCS2 payload {len(UD)}B exceeds 140B. Truncating.")
                    UD = UD[:140]
                UDL = len(UD)         
            else:
                DCS = 0x00            
                UDL = _gsm7_septet_len(text)          
                UD = _gsm7_pack(text)
                if len(UD) > 140:
                     self.log_error(f"[MO-FSM] 7-bit packed UD {len(UD)}B exceeds 140B. Truncating.")
                     UD = UD[:140]
                UDL = min(UDL, 160)                   
            return bytes([rp_mti, rp_mr]) + rp_da_ie + bytes([PID, DCS,UDL]) + UD
        smsc_str = smsc_str or CONFIG.get('smsc_gt') or CONFIG.get('remote_gt')
        if not smsc_str:
            raise ValueError("No SMSC address configured (set CONFIG['smsc_gt'] or provide --smsc).")
        oa_ton, oa_npi, oa_digits = _parse_ton_npi_digits(oa_str)                                  
        da_ton, da_npi, da_digits = _parse_ton_npi_digits(da_str)                             
        _ensure_digits("sm-RP-OA/OA", oa_digits)
        _ensure_digits("TP-DA/DA", da_digits)
        tpdu = _build_sms_submit_tpdu(da_ton, da_npi, da_digits, text)
        try:
            fo = tpdu[0] if len(tpdu) > 0 else None
            mr = tpdu[1] if len(tpdu) > 1 else None
            da_len = tpdu[2] if len(tpdu) > 2 else None
            idx = 3
            toa = None
            da_tbcd = b""
            if da_len is not None:
                if da_len == 0:
                    self.log_error("[MO-FSM] TP-DA length is 0 -> PID/DCS will be misaligned in Wireshark. Check DA digits and sanitization.")
                elif len(tpdu) > idx:
                    toa = tpdu[idx]; idx += 1
                    da_octets = (da_len + 1) // 2
                    if len(tpdu) >= idx + da_octets:
                        da_tbcd = tpdu[idx:idx + da_octets]
                        idx += da_octets
            pid = tpdu[idx] if len(tpdu) > idx else None
            dcs = tpdu[idx + 1] if len(tpdu) > idx + 1 else None
            if da_tbcd:
                pass
        except Exception as e:
            self.log_error(f"[MO-FSM] TPDU header parse error: {e}")
        rpdu = _build_rp_mo_data(da_ton,da_npi,da_digits, tpdu,text)
        smsc_ton, smsc_npi, smsc_digits = _parse_ton_npi_digits(smsc_str)
        smsc_addr = _build_address_string(smsc_ton, smsc_npi, smsc_digits)
        sm_rp_da = self.encode_asn1_tag_length(0x84, smsc_addr)
        oa_addr = _build_address_string(oa_ton, oa_npi, oa_digits)
        sm_rp_oa = self.encode_asn1_tag_length(0x82, oa_addr)
        sm_rp_ui = self.encode_asn1_tag_length(0x04, rpdu)
        imsi_param = b""
        imsi_str = CONFIG.get('imsi')
        if imsi_str:
            imsi_tbcd = self.encode_bcd_digits(_digits_only(imsi_str))
            imsi_param = self.encode_asn1_tag_length(0x04, imsi_tbcd)
        mo_arg = sm_rp_da + sm_rp_oa + sm_rp_ui + imsi_param
        param_seq = self.encode_asn1_tag_length(0x30, mo_arg)                                            
        invoke_id_enc = self.encode_asn1_tag_length(0x02, bytes([random.randint(1, 127)]))          
        opcode_local = self.encode_asn1_tag_length(0x02, bytes([46]))                        
        invoke = self.encode_asn1_tag_length(0xA1, invoke_id_enc + opcode_local + param_seq)             
        component_portion = self.encode_asn1_tag_length(0x6C, invoke)                    
        dialogue_as_id = self._encode_oid("0.0.17.773.1.1.1")                 
        aaq_pv = self.encode_asn1_tag_length(0x80, b"\x07\x80")                                  
        acn_oid = self._encode_oid("0.4.0.0.1.0.21.3")                             
        aaq_acn = self.encode_asn1_tag_length(0xA1, acn_oid)                               
        aaq = self.encode_asn1_tag_length(0x60, aaq_pv + aaq_acn)                            
        external = self.encode_asn1_tag_length(0x28, dialogue_as_id + self.encode_asn1_tag_length(0xA0, aaq))
        dialogue_portion = self.encode_asn1_tag_length(0x6B, external)                  
        otid_val = struct.pack("!I", random.randint(0x10000000, 0xFFFFFFFF))
        otid = self.encode_asn1_tag_length(0x48, otid_val)                             
        tcap_begin_data = otid + dialogue_portion + component_portion
        tcap_begin = self.encode_asn1_tag_length(0x62, tcap_begin_data)                  
        return tcap_begin
    def handle_console_command(self, line: str):
        parts = line.strip().split()
        if not parts:
            return
        cmd = parts[0].lower()
        if cmd in ('exit', 'quit'):
            self.stop()
            return
        if cmd in ('help', '?'):
            self.log_info("Commands:")
            self.log_info("  mo <oa-ton.npi.msisdn> <da-ton.npi.msisdn> <text> [--smsc ton.npi.addr]")
            self.log_info("  exit | quit")
            return
        if cmd == 'mo':
            if len(parts) < 4:
                self.log_error("Usage: mo <oa-ton.npi.msisdn> <da-ton.npi.msisdn> <text> [--smsc ton.npi.addr]")
                return
            oa = parts[1]
            da = parts[2]
            smsc = None
            text_tokens = parts[3:]
            i = 0
            while i < len(text_tokens):
                tok = text_tokens[i]
                if tok == '--smsc':
                    if i + 1 < len(text_tokens):
                        smsc = text_tokens[i + 1]
                        del text_tokens[i:i + 2]
                        continue
                    else:
                        self.log_error("Missing value after --smsc")
                        return
                elif tok.startswith('--smsc='):
                    smsc = tok.split('=', 1)[1]
                    del text_tokens[i]
                    continue
                else:
                    i += 1
            text = ' '.join(text_tokens)
            try:
                is_long = (any(ord(ch) > 0x7F for ch in text) and len(text) > 70) or\
                          ((not any(ord(ch) > 0x7F for ch in text)) and self._gsm7_septet_len_exact(text) > 160)
                if not is_long:                   
                    tcap = self.create_mo_fsm_invoke(oa, da, text, smsc)
                    called_gt = CONFIG.get('remote_gt') or CONFIG.get('smsc_gt')
                    calling_gt = CONFIG.get('msc_gt') or CONFIG.get('hlr_gt') or CONFIG.get('local_gt')
                    if not called_gt or not calling_gt:
                        self.log_error("Missing called or calling GT.")
                        return
                    ok = self._send_sccp_tcap_on_active(tcap, called_gt, calling_gt)
                    if not ok:
                        self.log_error("MO send failed (single).")
                    return                
                begin, our_otid, comps = self._plan_mo_segments(oa, da, text, smsc)
                called_gt = CONFIG.get('remote_gt') or CONFIG.get('smsc_gt')
                calling_gt = CONFIG.get('msc_gt') or CONFIG.get('hlr_gt') or CONFIG.get('local_gt')
                if not called_gt or not calling_gt:
                    self.log_error("Handshake: missing called/calling GT.")
                    return
                key = our_otid.hex()
                self.outgoing_dialogues[key] = {
                    'our_otid': our_otid,
                    'peer_otid': None,
                    'called_gt': called_gt,
                    'calling_gt': calling_gt,
                    'components': comps,                              
                    'next': 0,
                }
                ok = self._send_sccp_tcap_on_active(begin, called_gt, calling_gt)
                if ok:
                    self.log_info(f"MO handshake: Sent TCAP BEGIN (AARQ-only). Waiting for CONTINUE... (our_otid={key})")
                else:
                    self.log_error("MO handshake: failed to send TCAP BEGIN.")
            except Exception as e:
                self.log_error(f"MO command error: {e}")
            except Exception as e:
                import traceback
                self.log_error(f"MO command error: {e}")
                self.log_error("Traceback:\n" + traceback.format_exc())
                return
            return
    def start(self):
        try:
            self.socket = self.create_socket()
            if not self.socket:
                return
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            try:
                self.socket.settimeout(1.0)
            except Exception:
                pass
            if self.log_level in ['INFO', 'DEBUG']:
                self.log_info("=" * 60)
                self.log_info(f"Enhanced MAP SIGTRAN Server listening on {self.host}:{self.port}")
                self.log_info("Features:")
                self.log_info(" - MAP SRI-SM request handling")
                self.log_info(" - SRI-SM response with NNN and IMSI")
                self.log_info(" - Wireshark-like PDU logging")
                self.log_info(" - M3UA/SCCP/TCAP/MAP stack support")
                self.log_info(" - Console commands: 'mo <oa-ton.npi.msisdn> <da-ton.npi.msisdn> <text> [--smsc ton.npi.addr]'")
                self.log_info(" ")
                self.log_info("  mo 1.1.817085811456 1.1.817085811452 test")
                self.log_info(" ")
                self.log_info("  mo 1.1.817085811456 1.1.817085811452 簡訊服務 SMS；有時也稱為訊息、簡訊、文字訊息")
                self.log_info(" ")
                self.log_info("  mo 1.1.817085811456 1.1.817085811452 SEG1 This is segment 1 of the GSM/SMPP long message. It continues the structured transmission, ensuring clarity and coherence throughout. Segment 1 proviSEG2 This is segment 2 of the GSM/SMPP long message. It continues the structured transmission, ensuring clarity and coherence throughout. Segment 2 proviSEG3 This is segment 3 of the GSM/SMPP long message. It continues the structured transmission, ensuring clarity and coherence throughout. Segment 3 provi --smsc 1.1.817090514560")
                self.log_info(" ")
                self.log_info("  mo 1.1.817085811456 1.1.817085811452 當一則簡訊（SMS）超過標準長度限制時（例如 GSM 7-bit 編碼的 160 字元或 UCS-2 編碼的 70 字元），GSM 系統會使用（Concatenated SMS） 技術來分割並傳送訊息。每一部分都會附加一段特殊的資料，稱為 （UDH） UDH 是一段佔用空間的控制資訊，通常佔用 6 或 7 個位元組（bytes）。因此每一部分可用的字元數會比單一 SMS 少： GSM 7-bit 編碼：每段最多 153 字元 UCS-2 編碼：每段最多 67 字元 --smsc 1.1.817090514560")
                self.log_info("=" * 60)
            self.running = True
            def _console_loop():
                while self.running:
                    try:
                        line = sys.stdin.readline()
                        if not line:
                            time.sleep(0.05)
                            continue
                        self.handle_console_command(line)
                    except Exception as e:
                        self.log_error(f"Console error: {e}")
                        time.sleep(0.2)
            console_thread = threading.Thread(target=_console_loop, daemon=True)
            console_thread.start()
            while self.running:
                try:
                    conn, addr = self.socket.accept()
                    self.log_info(f"New SCTP connection from {addr[0]}:{addr[1]}")
                    conn_key = f"{addr[0]}:{addr[1]}"
                    self.asp_states.setdefault(conn_key, {})
                    self.asp_states[conn_key]['conn'] = conn
                    self.asp_states[conn_key]['addr'] = addr
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr),
                        daemon=True
                    )
                    client_thread.start()
                except socket.timeout:
                    continue
                except socket.error as e:
                    if self.running:
                        self.log_error(f"Accept error: {e}")
                    break
        except Exception as e:
            self.log_error(f"Failed to start server: {e}")
        finally:
            self.cleanup()
    def stop(self):
        self.log_info("Stopping Enhanced MAP SIGTRAN server...")
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
    def cleanup(self):
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.log_info("Enhanced MAP SIGTRAN server stopped")
def main():
    import argparse
    parser = argparse.ArgumentParser(description='Enhanced MAP SIGTRAN Server with configurable logging')
    parser.add_argument('--log-level', choices=['ERROR', 'INFO', 'DEBUG'], default='INFO',
                       help='Set logging level (ERROR: only errors, INFO: basic info + M3UA messages, DEBUG: detailed protocol traces)')
    parser.add_argument('--port', type=int, default=2905, help='Server port (default: 2905)')
    args = parser.parse_args()
    CONFIG['log_level'] = args.log_level
    server = MAPSIGTRANServer('0.0.0.0', args.port, args.log_level)
    try:
        server.start()
    except KeyboardInterrupt:
        if args.log_level in ['INFO', 'DEBUG']:
            print("\nShutdown requested...")
        server.stop()
    except Exception as e:
        if args.log_level in ['INFO', 'DEBUG']:
            print(f"Fatal error: {e}")
        else:
            print(f"Fatal error: {e}")                           
        server.stop()
if __name__ == "__main__":
    main()
