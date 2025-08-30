#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SMPP v3.4 Transceiver Client (robust framing + DLR TLVs + keepalive + SAR concatenation)

Design notes (spec-backed):
- PDU framing uses command_length and loops on TCP recv per SMPP 3.4. [Spec §2, §3]
- enquire_link_resp is header-only (16 bytes), NO body. [Spec §4.11][Ref]
- deliver_sm_resp body is message_id C-Octet String; empty "" is common. [Spec §4.7]
- DLR detection via esm_class bit 2; important TLVs parsed (001E, 0427, 0423). [DLR Guide]
- data_coding-aware encoding/decoding for short_message (0,3,8 pathways). [DCS Guide]
- NEW: Long-message support using SAR TLVs in submit_sm:
    * If data_coding == 8 (UCS-2), single-part limit is 70 chars; segmented parts are 67 chars.
    * Otherwise (e.g., GSM7-ish default / Latin-1), single-part limit is 160 chars; segmented parts are 153 chars.
    * When exceeding the single-part limit, the client splits text and sends multiple submit_sm PDUs with
      SAR optional parameters: sar_msg_ref_num (0x020C, 2 bytes), sar_total_segments (0x020E, 1 byte),
      sar_segment_seqnum (0x020F, 1 byte). This is an alternative to UDHI/UDH concatenation.
      (Note: some SMSCs expect UDHI; this client uses SAR by default.)
    * Demo main sends up to 3 segments (configurable).

References:
- SMPP v3.4 Specification (12-Oct-1999 Issue 1.2): https://smpp.org/SMPP_v3_4_Issue1_2.pdf
- DLR details & TLVs (message_state, receipted_message_id): https://smpp.org/smpp-delivery-receipt.html
- deliver_sm field order reference: https://melroselabs.com/docs/reference/smpp/deliver_sm/
- enquire_link_resp should not include a body: https://github.com/onlinecity/php-smpp/issues/49
- SAR concatenation via TLVs (sar_* params) and usage examples: https://docs.inetlab.com/smpp/v2/articles/concatenation.html
- Segment size rationale (160/153 for GSM7, 70/67 for UCS-2): 
  * https://nowsms.com/long-sms-text-messages-and-the-160-character-limit
  * https://api.support.vonage.com/hc/en-us/articles/204015653-How-do-I-send-concatenated-messages-via-SMPP
"""
import socket
import struct
import threading
import time
import logging
import math
import random
from typing import Dict, Tuple

# --------- Logging ---------
logging.basicConfig(level=logging.INFO, format='%(message)s')
def log_line(event: str, **kwargs):
    parts = [event]
    for k, v in kwargs.items():
        s = str(v).replace('\n', ' ').replace('\r', ' ')
        parts.append(f"{k}={s}")
    logging.info(" ".join(parts))

# --------- SMPP Constants ---------
# Command IDs
BIND_RECEIVER = 0x00000001
BIND_TRANSMITTER = 0x00000002
BIND_TRANSCEIVER = 0x00000009
OUTBIND = 0x0000000B
UNBIND = 0x00000006
UNBIND_RESP = 0x80000006
SUBMIT_SM = 0x00000004
SUBMIT_SM_RESP = 0x80000004
DELIVER_SM = 0x00000005
DELIVER_SM_RESP = 0x80000005
ENQUIRE_LINK = 0x00000015
ENQUIRE_LINK_RESP = 0x80000015
GENERIC_NACK = 0x80000000

# Command status
ESME_ROK = 0x00000000

# Useful TLV tags
TLV_RECEIPTED_MESSAGE_ID = 0x001E
TLV_MESSAGE_STATE = 0x0427
TLV_NETWORK_ERROR_CODE = 0x0423

# NEW: SAR TLVs for concatenation (SMPP 3.4)
TLV_SAR_MSG_REF_NUM     = 0x020C  # 2 bytes (reference for all parts)
TLV_SAR_TOTAL_SEGMENTS  = 0x020E  # 1 byte
TLV_SAR_SEGMENT_SEQNUM  = 0x020F  # 1 byte

# SMPP Status Codes (partial)
SMPP_STATUS_CODES = {
    0x00000000: "OK",
    0x00000001: "Message length is invalid",
    0x00000002: "Command length is invalid",
    0x00000003: "Invalid command ID",
    0x00000004: "Incorrect bind status for given command",
    0x00000005: "ESME already in bound state",
    0x00000006: "Invalid priority flag",
    0x0000000A: "Invalid source address",
    0x0000000B: "Invalid destination address",
    0x0000000D: "Message queue full",
    0x0000000E: "Invalid service type",
    0x0000000F: "Invalid message ID",
    0x00000011: "Invalid TLV parameter",
    0x00000014: "Invalid bind status",
    0x00000015: "Invalid submit_sm parameters",
    0x00000021: "System error",
    0x00000032: "Network error",
    0x00000064: "Message rejected",
}
def decode_status_code(code: int) -> str:
    msg = SMPP_STATUS_CODES.get(code, "Unknown error")
    if msg == "Unknown error":
        logging.warning(f"Unknown SMPP status code: {code:#010x}")
    return msg

# --------- Sequence Number ---------
class SeqGen:
    def __init__(self, start=0):
        self._s = start
        self._lock = threading.Lock()
    def next(self) -> int:
        with self._lock:
            self._s = 1 if self._s >= 0x7fffffff else self._s + 1
            return self._s

# --------- Socket helpers (robust TCP framing) ---------
def read_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed while reading")
        buf += chunk
    return bytes(buf)

def read_one_pdu(sock: socket.socket) -> bytes:
    header = read_exact(sock, 16)
    command_length, cmd_id, cmd_status, seq = struct.unpack('>IIII', header)
    if command_length < 16:
        raise ValueError(f"Invalid command_length={command_length}")
    body_len = command_length - 16
    body = read_exact(sock, body_len) if body_len else b''
    return header + body

# --------- C-Octet string helper ---------
def decode_cstring(b: bytes) -> Tuple[str, bytes]:
    i = b.find(b'\x00')
    if i == -1:
        return "", b
    return b[:i].decode('ascii', errors='replace'), b[i+1:]

# --------- TLV pack helper ---------
def _pack_tlv(tag: int, value: bytes) -> bytes:
    """Pack a TLV (Tag-Length-Value) as per SMPP: tag(2) length(2) value(N)."""
    return struct.pack('>HH', tag, len(value)) + value

# --------- SMPP Client ---------
class SMPPClient:
    def __init__(self, host: str, port: int, system_id: str, password: str,
                 system_type: str = '', enquire_interval: int = 30):
        self.host = host
        self.port = port
        self.system_id = system_id
        self.password = password
        self.system_type = system_type
        self.enquire_interval = enquire_interval
        self.sock: socket.socket = None
        self.seq = SeqGen()
        self.keepalive_stop = threading.Event()
        self.keepalive_thr: threading.Thread = None

    # ---- connection ----
    def connect(self, timeout=30):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect((self.host, self.port))
        log_line("tcp_connected", host=self.host, port=self.port)

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        finally:
            self.sock = None
            log_line("tcp_closed")

    # ---- PDUs ----
    def send_pdu(self, cmd_id: int, cmd_status: int, seq: int, body: bytes = b''):
        header = struct.pack('>IIII', 16 + len(body), cmd_id, cmd_status, seq)
        self.sock.sendall(header + body)

    # ---- bind ----
    def bind_transceiver(self) -> int:
        interface_version = b'\x34'  # v3.4
        addr_ton = b'\x00'
        addr_npi = b'\x00'
        addr_range = b'\x00'
        body = (
            self.system_id.encode() + b'\x00' +
            self.password.encode() + b'\x00' +
            self.system_type.encode() + b'\x00' +
            interface_version + addr_ton + addr_npi + addr_range
        )
        seq = self.seq.next()
        self.send_pdu(BIND_TRANSCEIVER, 0, seq, body)
        log_line("bind_transceiver_req", sys_id=self.system_id, sys_type=self.system_type or "", if_ver=0x34, seq=seq)
        return seq

    # ---- submit_sm (now supports optional TLVs + esm_class override) ----
    def submit_sm(self, source_addr: str, dest_addr: str, short_message: str,
                  data_coding_val: int = 0,
                  tlvs: Dict[int, bytes] = None,
                  esm_class_val: int = 0x00) -> int:
        # Select encoding per DCS
        if data_coding_val == 8:
            sm_content = short_message.encode('utf-16-be')
        elif data_coding_val == 3:
            sm_content = short_message.encode('latin-1', errors='replace')
        else:  # 0 = GSM 03.38 (approximate with ASCII fallback here)
            sm_content = short_message.encode('ascii', errors='replace')

        sm_length = struct.pack('B', len(sm_content))
        service_type = b'\x00'
        source_addr_ton = b'\x01'
        source_addr_npi = b'\x01'
        dest_addr_ton = b'\x01'
        dest_addr_npi = b'\x01'
        esm_class = struct.pack('B', esm_class_val)  # allow UDHI if needed; default 0x00
        protocol_id = b'\x00'
        priority_flag = b'\x00'
        schedule_delivery_time = b'\x00'
        validity_period = b'\x00'
        registered_delivery = b'\x01'  # final DLR (success/failure)
        replace_if_present = b'\x00'
        data_coding = struct.pack('B', data_coding_val)
        sm_default_msg_id = b'\x00'

        body = (
            service_type +
            source_addr_ton + source_addr_npi + source_addr.encode() + b'\x00' +
            dest_addr_ton + dest_addr_npi + dest_addr.encode() + b'\x00' +
            esm_class + protocol_id + priority_flag +
            schedule_delivery_time + validity_period +
            registered_delivery + replace_if_present + data_coding + sm_default_msg_id +
            sm_length + sm_content
        )

        # Append TLVs if any
        if tlvs:
            for tag, val in tlvs.items():
                body += _pack_tlv(tag, val)

        seq = self.seq.next()
        self.send_pdu(SUBMIT_SM, 0, seq, body)
        log_line("submit_sm_req", src=source_addr, dst=dest_addr, len=len(sm_content), dcs=data_coding_val, seq=seq, msg=short_message)
        return seq

    # ---- High-level text submission with auto segmentation using SAR TLVs ----
    def submit_text_segmented(self,
                              source_addr: str,
                              dest_addr: str,
                              text: str,
                              data_coding_val: int = 0,
                              max_segments: int = 3):
        """
        Enforce per-DCS character limits and, when necessary, split text and send
        multiple submit_sm PDUs using SAR TLVs. Returns list of sequence numbers.

        - For DCS=8 (UCS-2): 70 chars single-part, 67 per segment when concatenated.
        - For others (e.g. GSM7-ish/Latin-1): 160 chars single-part, 153 per concatenated segment.
        See: NowSMS long-SMS guide, Vonage concatenation article, SMPP 3.4 spec.
        """
        # Determine character budgets per DCS
        if data_coding_val == 8:
            single_limit = 70
            per_part = 67
        else:
            single_limit = 160
            per_part = 153

        # If fits in one part, just send it
        if len(text) <= single_limit:
            return [self.submit_sm(source_addr, dest_addr, text, data_coding_val)]

        # Needs segmentation
        total_parts_full = math.ceil(len(text) / per_part)

        # Enforce max_segments if specified (>0). If exceeded, truncate and warn.
        if max_segments is None or max_segments <= 0:
            total_parts = total_parts_full
        else:
            total_parts = min(total_parts_full, max_segments)
            if total_parts_full > max_segments:
                log_line("warn_truncate_segments", reason="exceeds_max_segments",
                         need=total_parts_full, max=max_segments)

        # 16-bit reference number for all parts
        ref_num = random.randint(0, 0xFFFF)

        seqs = []
        for i in range(total_parts):
            start = i * per_part
            end = start + per_part
            segment_text = text[start:end]

            # Build SAR TLVs
            tlvs = {
                TLV_SAR_MSG_REF_NUM: struct.pack('>H', ref_num),       # 2 bytes
                TLV_SAR_TOTAL_SEGMENTS: struct.pack('B', total_parts), # 1 byte
                TLV_SAR_SEGMENT_SEQNUM: struct.pack('B', i + 1),       # 1 byte
            }

            # With SAR TLVs we keep esm_class=0x00 (no UDHI); SMSC may generate UDH.
            seq = self.submit_sm(source_addr, dest_addr, segment_text,
                                 data_coding_val=data_coding_val,
                                 tlvs=tlvs,
                                 esm_class_val=0x00)
            log_line("submit_sm_part", part=i+1, total=total_parts, ref=ref_num, seq=seq,
                     chars=len(segment_text), dcs=data_coding_val)
            seqs.append(seq)
            time.sleep(0.5)

        return seqs

    # ---- enquire_link (keepalive) ----
    def send_enquire_link(self):
        seq = self.seq.next()
        self.send_pdu(ENQUIRE_LINK, 0, seq, b'')  # header only
        log_line("enquire_link_tx", seq=seq)

    def _keepalive_loop(self):
        while not self.keepalive_stop.wait(self.enquire_interval):
            try:
                self.send_enquire_link()
            except Exception as e:
                log_line("keepalive_error", err=e)
                break

    def start_keepalive(self):
        self.keepalive_stop.clear()
        self.keepalive_thr = threading.Thread(target=self._keepalive_loop, name="smpp-keepalive", daemon=True)
        self.keepalive_thr.start()

    def stop_keepalive(self):
        self.keepalive_stop.set()
        if self.keepalive_thr and self.keepalive_thr.is_alive():
            self.keepalive_thr.join(timeout=2)

    # ---- unbind ----
    def unbind(self):
        seq = self.seq.next()
        self.send_pdu(UNBIND, 0, seq, b'')
        log_line("unbind_tx", seq=seq)
        # Best-effort read of UNBIND_RESP
        try:
            pdu = read_one_pdu(self.sock)
            cmd_len, cmd_id, cmd_status, rseq = struct.unpack('>IIII', pdu[:16])
            if cmd_id == UNBIND_RESP:
                log_line("unbind_resp", status=decode_status_code(cmd_status), seq=rseq)
        except Exception:
            pass

    # ---- reading/dispatch ----
    def read_until_bound(self, timeout=30) -> bool:
        """Read PDUs until we receive a successful bind_transceiver_resp."""
        end = time.time() + timeout
        while time.time() < end:
            pdu = read_one_pdu(self.sock)
            cmd_len, cmd_id, cmd_status, seq = struct.unpack('>IIII', pdu[:16])
            body = pdu[16:]
            if cmd_id == GENERIC_NACK:
                log_line("generic_nack", status=decode_status_code(cmd_status), seq=seq)
            elif cmd_id == BIND_TRANSCEIVER + 0x80000000:
                system_id = body.split(b'\x00', 1)[0].decode('utf-8', errors='replace') if body else ""
                log_line("bind_transceiver_resp", status=decode_status_code(cmd_status), sys_id=system_id, seq=seq)
                return cmd_status == 0
            elif cmd_id == ENQUIRE_LINK:
                self._handle_enquire_link(seq)
            else:
                # Defer other PDUs until after bind
                log_line("prebind_pdu", cmd_id=cmd_id, seq=seq)
        return False

    def serve_forever(self):
        """Main receive loop after successful bind."""
        while True:
            pdu = read_one_pdu(self.sock)
            self._handle_pdu(pdu)

    def _handle_pdu(self, pdu: bytes):
        cmd_len, cmd_id, cmd_status, seq = struct.unpack('>IIII', pdu[:16])
        body = pdu[16:]
        if cmd_id == GENERIC_NACK:
            log_line("generic_nack", status=decode_status_code(cmd_status), seq=seq)
        elif cmd_id == ENQUIRE_LINK:
            self._handle_enquire_link(seq)
        elif cmd_id == ENQUIRE_LINK_RESP:
            log_line("enquire_link_resp", status=decode_status_code(cmd_status), seq=seq)
        elif cmd_id == SUBMIT_SM_RESP:
            # message_id is a C-Octet String in body (may be null or text)
            msg_id = body.split(b'\x00', 1)[0].decode('ascii', errors='replace') if body else ""
            log_line("submit_sm_resp", status=decode_status_code(cmd_status), seq=seq, msg_id=msg_id)
        elif cmd_id == DELIVER_SM:
            info = self._decode_deliver_sm(pdu)
            is_dlr = bool(info['esm_class'] & 0x04)
            # Prefer TLVs when present, else log short_message
            fields = {
                "seq": info['sequence_number'],
                "status": decode_status_code(info['command_status']),
                "src": info['source_addr'],
                "dst": info['dest_addr'],
                "esm_class": info['esm_class'],
                "dcs": info['data_coding'],
                "len": info['sm_length'],
            }
            if is_dlr:
                fields["kind"] = "DLR"
                if info.get("tlv_receipted_message_id"):
                    fields["rcpt_msg_id"] = info["tlv_receipted_message_id"]
                if info.get("tlv_message_state") is not None:
                    fields["msg_state"] = info["tlv_message_state"]  # 0..8
                fields["text"] = info['short_message']  # text receipt if provided
            else:
                fields["kind"] = "MO"
                fields["text"] = info['short_message']
            log_line("deliver_sm", **fields)
            # Respond with deliver_sm_resp: message_id as empty C-string
            resp_body = b'\x00'  # empty message_id
            self.send_pdu(DELIVER_SM_RESP, ESME_ROK, info['sequence_number'], resp_body)
            # log_line("deliver_sm_resp", seq=info['sequence_number'], status="OK")
        elif cmd_id == UNBIND:
            # peer requests unbind; acknowledge and close
            self.send_pdu(UNBIND_RESP, ESME_ROK, seq, b'')
            log_line("unbind_resp", seq=seq, status="OK (peer-initiated)")
            self.close()
        else:
            log_line("unknown_pdu", cmd_id=cmd_id, seq=seq)

    def _handle_enquire_link(self, seq: int):
        # respond with header-only (no body)
        self.send_pdu(ENQUIRE_LINK_RESP, ESME_ROK, seq, b'')
        log_line("enquire_link_resp", seq=seq, status="OK")

    # ---- deliver_sm decode (mandatory fields + TLVs) ----
    def _decode_deliver_sm(self, pdu: bytes) -> Dict:
        header = pdu[:16]
        body = pdu[16:]
        command_length, command_id, command_status, sequence_number = struct.unpack('>IIII', header)
        service_type, body = decode_cstring(body)
        source_addr_ton = body[0]
        source_addr_npi = body[1]
        source_addr, body = decode_cstring(body[2:])
        dest_addr_ton = body[0]
        dest_addr_npi = body[1]
        dest_addr, body = decode_cstring(body[2:])
        esm_class = body[0]
        protocol_id = body[1]
        priority_flag = body[2]
        schedule_delivery_time, body = decode_cstring(body[3:])
        validity_period, body = decode_cstring(body)
        registered_delivery = body[0]
        replace_if_present_flag = body[1]
        data_coding = body[2]
        sm_default_msg_id = body[3]
        sm_length = body[4]
        sm_bytes = body[5:5+sm_length]
        rest = body[5+sm_length:]  # TLVs

        # decode short_message based on DCS
        if data_coding == 8:
            short_message = sm_bytes.decode('utf-16-be', errors='replace')
        elif data_coding == 3:
            short_message = sm_bytes.decode('latin-1', errors='replace')
        else:
            short_message = sm_bytes.decode('ascii', errors='replace')

        # TLVs
        tlvs = {}
        while len(rest) >= 4:
            tag, length = struct.unpack('>HH', rest[:4])
            value = rest[4:4+length]
            rest = rest[4+length:]
            tlvs[tag] = value

        rcvd_msg_id = tlvs.get(TLV_RECEIPTED_MESSAGE_ID, b'').decode('ascii', errors='replace') if TLV_RECEIPTED_MESSAGE_ID in tlvs else ""
        msg_state = tlvs.get(TLV_MESSAGE_STATE)
        if msg_state is not None and len(msg_state) == 1:
            msg_state = msg_state[0]

        return {
            "command_id": command_id,
            "command_status": command_status,
            "sequence_number": sequence_number,
            "service_type": service_type,
            "source_addr_ton": source_addr_ton,
            "source_addr_npi": source_addr_npi,
            "source_addr": source_addr,
            "dest_addr_ton": dest_addr_ton,
            "dest_addr_npi": dest_addr_npi,
            "dest_addr": dest_addr,
            "esm_class": esm_class,
            "protocol_id": protocol_id,
            "priority_flag": priority_flag,
            "schedule_delivery_time": schedule_delivery_time,
            "validity_period": validity_period,
            "registered_delivery": registered_delivery,
            "replace_if_present_flag": replace_if_present_flag,
            "data_coding": data_coding,
            "sm_default_msg_id": sm_default_msg_id,
            "sm_length": sm_length,
            "short_message": short_message,
            "tlv_receipted_message_id": rcvd_msg_id,
            "tlv_message_state": msg_state,
            "tlv_network_error_code": tlvs.get(TLV_NETWORK_ERROR_CODE),
        }

# ----------- Demo main -----------
def main():
    # --- CONFIG: set your SMSC and credentials here ---
    CONFIG = {
        "smsc_host": "127.0.0.1",
        "smsc_port": 9000,
        "system_id": "SMPP_TEST",
        "password": "pooky",
        "system_type": "",
        "source_addr": "817083615020",
        "dest_addr": "817083615021",
        # Try a long message to exercise segmentation:
        "short_message": "This is a long test message that will be automatically split "
                         "into multiple SAR-based segments when it exceeds the per-part "
                         "limits. " * 15,
        "data_coding": 0,  # 0=GSM7/ASCII-ish, 3=Latin-1, 8=UCS-2
        "enquire_interval": 30,  # seconds
        "max_segments": 10  # demo cap: send up to 3 segments
    }

    c = SMPPClient(CONFIG["smsc_host"], CONFIG["smsc_port"],
                   CONFIG["system_id"], CONFIG["password"],
                   CONFIG["system_type"], CONFIG["enquire_interval"])
    try:
        c.connect()
        c.bind_transceiver()
        # Wait for bind response (success) before proceeding
        if not c.read_until_bound(timeout=30):
            log_line("bind_result", result="error")
            return
        log_line("bind_result", result="success")

        # Start periodic enquire_link to keep the session alive
        c.start_keepalive()

        # Submit (auto-segment with SAR if needed). Sends up to max_segments parts.
        c.submit_text_segmented(CONFIG["source_addr"], CONFIG["dest_addr"],
                                CONFIG["short_message"], CONFIG["data_coding"],
                                max_segments=CONFIG["max_segments"])

        # Enter receive loop (Ctrl-C to stop)
        c.serve_forever()
    except KeyboardInterrupt:
        log_line("signal", sig="CTRL-C")
    except Exception as e:
        log_line("error", err=e)
    finally:
        try:
            c.stop_keepalive()
            # Attempt graceful unbind if socket still valid
            if c.sock:
                c.unbind()
        except Exception:
            pass
        c.close()



if __name__ == "__main__":
    main()
