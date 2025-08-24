#!/usr/bin/env python3
"""
Enhanced SIGTRAN Server with MAP SRI-SM Support
Handles MAP Send Routing Info for Short Message requests
Supports M3UA/SCCP/TCAP/MAP protocol stack with IMSI and NNN response
Requires root privileges for native SCTP
Logs PDUs in Wireshark-like format similar to tshark -nr test.capy -Y tcap -t ad -V
"""

import socket
import struct
import threading
import logging
import time
import random
import os
import sys
from datetime import datetime

# SCTP Protocol Number
IPPROTO_SCTP = 132
SCCP_XUDT = 0x11       # Extended Unitdata

# Configuration
CONFIG = {
    'local_gt': '817085811990',
    'local_pc': 641,
    'remote_gt': '817090514123', 
    'remote_pc': 2990,
    'route_context': 34,
    'ssn': 6,  # HLR SSN
    'network_indicator': 3,  # International network
    'hlr_gt': '817085811990',  # HLR Global Title
    'msc_gt': '817085811990',  # MSC Global Title for NNN
    'vlr_gt': '817085811990',  # VLR Global Title
    'log_level': 'INFO'  # ERROR, INFO, DEBUG
}

# M3UA Message Classes
M3UA_MGMT_CLASS = 0
M3UA_TRANSFER_CLASS = 1
M3UA_SSNM_CLASS = 2
M3UA_ASPSM_CLASS = 3
M3UA_ASPTM_CLASS = 4
M3UA_RKM_CLASS = 5

# M3UA Message Types
M3UA_DATA = 1          # Transfer Class
M3UA_ASPUP = 1         # ASPSM Class
M3UA_ASPDN = 2
M3UA_BEAT = 3
M3UA_ASPUP_ACK = 4
M3UA_ASPDN_ACK = 5
M3UA_BEAT_ACK = 6
M3UA_ASPAC = 1         # ASPTM Class
M3UA_ASPIA = 2
M3UA_ASPAC_ACK = 3
M3UA_ASPIA_ACK = 4
M3UA_ERR = 0           # MGMT Class
M3UA_NTFY = 1

# M3UA Parameters
M3UA_PARAM_NETWORK_APPEARANCE = 0x0200
M3UA_PARAM_ROUTING_CONTEXT = 0x0006
M3UA_PARAM_PROTOCOL_DATA = 0x0210
M3UA_PARAM_CORRELATION_ID = 0x0013
M3UA_PARAM_INFO_STRING = 0x0004
M3UA_PARAM_TRAFFIC_MODE_TYPE = 0x000b
M3UA_PARAM_ASP_IDENTIFIER = 0x0011

# SCCP Message Types
SCCP_UDT = 0x09        # Unitdata
SCCP_UDTS = 0x0A       # Unitdata Service

# SCCP Address Indicators
SCCP_AI_PC_PRESENT = 0x01
SCCP_AI_ROUTING_GT = 0x00    # Route on GT  
SCCP_AI_GT_PRESENT = 0x04    # GT present
SCCP_AI_SSN_PRESENT = 0x02   # SSN present

# TCAP Message Types
TCAP_BEGIN = 0x62
TCAP_CONTINUE = 0x65
TCAP_END = 0x64
TCAP_ABORT = 0x67

# MAP Operation Codes
MAP_SRI_SM = 45        # Send Routing Info for SM
MAP_SRI_SM_RESP = 45   # Same opcode for response

MAP_MT_FSM = 44        # Forward Short Message
MAP_MT_FSM_RESP = 44   # Same opcode for response



# ASN.1 Tags
ASN1_SEQUENCE = 0x30
ASN1_CONTEXT_0 = 0x80
ASN1_CONTEXT_1 = 0x81
ASN1_CONTEXT_2 = 0x82
ASN1_INTEGER = 0x02
ASN1_OCTET_STRING = 0x04

class M3UAMessage:
    """M3UA Message Structure"""
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
    """M3UA Parameter TLV"""
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
    """SCCP Address encoding"""
    def __init__(self, gt=None, pc=None, ssn=None):
        self.gt = gt
        self.pc = pc
        self.ssn = ssn
 
    def pack(self):
        # Address Indicator (Q.713):
        # bit7: national use
        # bit6: Routing indicator (0 = route on GT, 1 = route on PC/SSN)
        # bits5..2: GTI (Global Title Indicator)
        # bit1: SSN present
        # bit0: PC present

        gti = 0x04 if self.gt else 0x00  # 4 = TT + NP/ES + NAI + digits
        ai = (gti & 0x0F) << 2           # bit6 stays 0 => route on GT
        if self.ssn is not None:
            ai |= SCCP_AI_SSN_PRESENT    # 0x02
        if self.pc is not None:
            ai |= SCCP_AI_PC_PRESENT     # 0x01

        addr_data = struct.pack('!B', ai)

        # Point Code (if present)
        if self.pc is not None:
            addr_data += struct.pack('<H', self.pc)

        # SSN (if present)
        if self.ssn is not None:
            addr_data += struct.pack('!B', self.ssn)

        # Global Title (if present): GTI = 4 => TT, NP/ES, NAI, digits
        if self.gt:
            digit_count = len(self.gt)
            es = 0x01 if (digit_count % 2 == 1) else 0x02   # 1=odd, 2=even
            np_es = (0x01 << 4) | es                        # NP=1 (E.164) | ES
            nai = 0x04                                      # International number

            # TT=0x00 (default), NP/ES, NAI
            gt_data = struct.pack('!BBB', 0x00, np_es, nai)

            # TBCD digits: low nibble = first digit, high nibble = second digit
            gt_digits = self.gt
            if digit_count % 2:
                gt_digits += 'F'  # pad F for odd number of digits

            for i in range(0, len(gt_digits), 2):
                first = gt_digits[i]
                second = gt_digits[i + 1] if i + 1 < len(gt_digits) else 'F'
                d_low = 15 if first == 'F' else int(first)
                d_high = 15 if second == 'F' else int(second)
                gt_data += bytes([(d_high << 4) | d_low])  # (second<<4) | first

            addr_data += gt_data

        return struct.pack('!B', len(addr_data)) + addr_data


class MAPSIGTRANServer:
    """Enhanced SIGTRAN Server with MAP SRI-SM Support and Configurable Logging"""
    
    def __init__(self, host='0.0.0.0', port=2915, log_level='INFO'):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.asp_states = {}
        self.transaction_id = 1
        self.active_transactions = {}
        self.log_level = log_level.upper()
        
        # Setup logging with configurable levels
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
        """Setup logging with configurable levels"""
        # Create logger
        self.logger = logging.getLogger('MAPSIGTRANServer')
        self.logger.setLevel(logging.DEBUG)  # Set to lowest level, handlers will filter
        
        # Clear any existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # File handler - always write DEBUG level to file
        file_handler = logging.FileHandler('map_sigtran_server.log')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter('%(message)s')
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        # Console handler with configurable level
        if self.log_level != 'ERROR':  # ERROR level shows nothing on console
            console_handler = logging.StreamHandler()
            if self.log_level == 'INFO':
                console_handler.setLevel(logging.INFO)
            elif self.log_level == 'DEBUG':
                console_handler.setLevel(logging.DEBUG)
            
            console_formatter = logging.Formatter('%(message)s')
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)
        
        # Prevent propagation to root logger
        self.logger.propagate = False
    
    def log_info(self, message):
        """Log INFO level message"""
        self.logger.info(message)
    
    def log_debug(self, message):
        """Log DEBUG level message"""
        self.logger.debug(message)
    
    def log_error(self, message):
        """Log ERROR level message"""
        self.logger.error(message)
    
    def check_sctp_support(self):
        """Check if kernel supports SCTP"""
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_SCTP)
            test_sock.close()
            self.log_info("SCTP support verified")
            return True
        except (OSError, socket.error) as e:
            self.log_error(f"SCTP not supported: {e}")
            self.log_error("Install SCTP support: sudo apt-get install libsctp-dev")
            return False
    
    def create_socket(self):
        """Create SCTP socket"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_SCTP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.log_info("Created native SCTP socket")
            return sock
        except Exception as e:
            self.log_error(f"Failed to create SCTP socket: {e}")
            return None
    
    def create_m3ua_response(self, req_class, req_type, parameters=None):
        """Create M3UA response message"""
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
        """Generate IMSI based on MSISDN with proper 15-digit format"""
        mcc = "440"  # Japan
        mnc = "11"   # Sample network
    
        if len(msisdn) >= 9:
            msin = msisdn[-9:]  # Take last 9 digits
        else:
            msin = msisdn.zfill(9)  # Pad if shorter
    
        imsi = mcc + mnc + msin
        if len(imsi) != 15:
            imsi = imsi[:15].ljust(15, '0')
        #imsi = "440110287841432"
        self.log_debug(f"Generated IMSI: {imsi} from MSISDN: {msisdn}")
        return imsi
  
    def encode_bcd_digits(self, digits_str):
        """
        Encode decimal digits to TBCD (nibble-swapped):
          - low nibble  = first digit
          - high nibble = second digit
          - pad with 'F' if odd number of digits
        """
        digits = digits_str
        if len(digits) % 2:
            digits += 'F'

        out = bytearray()
        for i in range(0, len(digits), 2):
            first = digits[i]      # low nibble
            second = digits[i+1]   # high nibble
            d_low = 15 if first == 'F' else int(first)
            d_high = 15 if second == 'F' else int(second)
            out.append((d_high << 4) | d_low)

        self.log_debug(f"Encoded BCD '{digits_str}' -> {out.hex()}")
        return bytes(out)

    def encode_asn1_tag_length(self, tag: int, data: bytes) -> bytes:
        """
        Encode ASN.1 TLV with BER definite form length.
        Uses short form for length < 128; long form otherwise.
        """
        length = len(data)
        if length < 0x80:
            return bytes([tag, length]) + data
        # Long form: first length byte = 0x80 | number_of_length_octets
        length_bytes = []
        tmp = length
        while tmp > 0:
            length_bytes.insert(0, tmp & 0xFF)
            tmp >>= 8
        if len(length_bytes) > 127:
            raise ValueError("Length too large for ASN.1 encoding")
        return bytes([tag, 0x80 | len(length_bytes)]) + bytes(length_bytes) + data

    def _encode_oid(self, dotted: str) -> bytes:
        """
        Encode dotted OID string to BER (X.690) bytes (tag 0x06 + length + value).
        """
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
        return self.encode_asn1_tag_length(0x06, value)  # OBJECT IDENTIFIER

    def _build_tcap_dialogue_portion_aare(self, acn_oid: str = "0.4.0.0.1.0.20.3") -> bytes:
        dialogue_as_id = self._encode_oid("0.0.17.773.1.1.1")
        aare_pv = self.encode_asn1_tag_length(0x80, b"\x07\x80")
        acn_inner = self._encode_oid(acn_oid)
        aare_acn = self.encode_asn1_tag_length(0xA1, acn_inner)
        aare_result = self.encode_asn1_tag_length(0xA2, b"\x02\x01\x00")  # corrected
        rsd_inner = self.encode_asn1_tag_length(0xA1, b"\x02\x01\x00")
        aare_rsd = self.encode_asn1_tag_length(0xA3, rsd_inner)
        aare_payload = aare_pv + aare_acn + aare_result + aare_rsd
        aare = self.encode_asn1_tag_length(0x61, aare_payload)
        single_asn1 = self.encode_asn1_tag_length(0xA0, aare)
        external = self.encode_asn1_tag_length(0x28, dialogue_as_id + single_asn1)
        dialogue_portion = self.encode_asn1_tag_length(0x6B, external)
        return dialogue_portion


    def create_mt_fsm_response(self, invoke_id: int, op_code: int, orig_transaction_id: bytes):
      """
      Build TCAP END + ReturnResultLast for (MT|MO)-ForwardSM.
      - invoke_id: from the incoming component
      - op_code:   echo the incoming op (44=MT-FSM v3, 46=MO-FSM or v1/v2 ForwardSM)
      - orig_transaction_id: caller's OTID from BEGIN; becomes our DTID in END
      """
      try:
        self.log_debug("=" * 50)
        self.log_debug("Creating MT-FSM Response:")

        # --- ReturnResultLast content ---------------------------------------
        # invokeID (INTEGER)
        invoke_id_enc = self.encode_asn1_tag_length(0x02, bytes([invoke_id & 0xFF]))

       
        rrl_content = invoke_id_enc 
        component = self.encode_asn1_tag_length(0xA2, rrl_content)       # [2] returnResultLast
        component_portion = self.encode_asn1_tag_length(0x6C, component)  # Component Portion

        # --- Transaction IDs -------------------------------------------------
        if orig_transaction_id and 1 <= len(orig_transaction_id) <= 4:
            dtid_value = orig_transaction_id
        else:
            import random, struct
            dtid_value = struct.pack('!I', random.randint(0x10000000, 0xFFFFFFFF))
        dtid = self.encode_asn1_tag_length(0x49, dtid_value)              # DTID for END

        # --- Dialogue Portion: AARE with MT-Relay ACN -----------------------
        # shortMsgMT-RelayContext-v3 OID = 0.4.0.0.1.0.25.3
        dialogue_portion = self._build_tcap_dialogue_portion_aare("0.4.0.0.1.0.25.3")  # ACN for MT-FSM v3
        # (If you’re handling legacy ForwardSM without ACN, AARE is still fine.)

        # --- TCAP END --------------------------------------------------------
        tcap_end_data = dtid + dialogue_portion + component_portion
        tcap_end = self.encode_asn1_tag_length(0x64, tcap_end_data)       # TC-END

        # Logs
        self.log_debug(f"  TCAP End message created: {len(tcap_end)} bytes")
        self.log_debug(f"  Complete TCAP End: {tcap_end.hex()}")
        self.log_debug("=" * 50)
        return tcap_end

      except Exception as e:
        self.log_error(f"Error creating MT-FSM Response: {e}")
        return None
        
 

    def create_sri_sm_response(self, invoke_id, msisdn, orig_transaction_id):
        """Create MAP SRI-SM ReturnResultLast within TCAP END (with Dialogue Portion AARE)."""
        self.log_debug("=" * 50)
        self.log_debug("Creating SRI-SM Response:")
        self.log_debug(f"  MSISDN: {msisdn}")
        self.log_debug(f"  Invoke ID: {invoke_id}")
        self.log_debug(f"  Original Transaction ID: {orig_transaction_id.hex() if orig_transaction_id else 'None'}")

        # ---- helpers (local) ---------------------------------------------------------
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
            return self.encode_asn1_tag_length(0x06, bytes(out))  # OBJECT IDENTIFIER

        # ---- validate invoke id ------------------------------------------------------
        if not (0 <= invoke_id <= 255):
            self.log_error(f"Invalid invoke ID: {invoke_id}")
            invoke_id &= 0xFF

        # ---- build MAP result (RoutingInfoForSM-Res) ---------------------------------
        imsi = self.generate_imsi(msisdn)
        nnn_gt = CONFIG['msc_gt']

        # AddressString = TON/NPI(0x91) + TBCD digits
        ton_npi = 0x91
        nnn_bcd = self.encode_bcd_digits(nnn_gt)
        nnn_address_string = bytes([ton_npi]) + nnn_bcd

        # IMSI (TBCD) and LMSI
        imsi_bcd = self.encode_bcd_digits(imsi)
        imsi_element = self.encode_asn1_tag_length(0x04, imsi_bcd)
    
        # locationInfoWithLMSI ::= [0] SEQUENCE { networkNode-Number [1] ISDN-AddressString, lmsi OCTET STRING OPTIONAL, ... }
        li_inner = (
            self.encode_asn1_tag_length(0x81, nnn_address_string)                  # [1] networkNode-Number
        )
        location_info = self.encode_asn1_tag_length(0xa0, li_inner)                 # [0] constructed

        result_param_content = imsi_element + location_info

        # ---- TCAP component: ReturnResultLast ---------------------------------------
        # invokeID (INTEGER)
        invoke_id_encoded = self.encode_asn1_tag_length(0x02, bytes([invoke_id]))

        # result ::= SEQUENCE { opCode, parameter }
        op_code_local = self.encode_asn1_tag_length(0x02, bytes([45]))              # [0] localValue = 45
        parameter_seq = self.encode_asn1_tag_length(0x30, result_param_content)     # parameter SEQUENCE
        result_seq = self.encode_asn1_tag_length(0x30, op_code_local + parameter_seq)

        # ReturnResultLast content: invokeID + result
        rrl_content = invoke_id_encoded + result_seq
        component = self.encode_asn1_tag_length(0xA2, rrl_content)                  # [2] returnResultLast
        component_portion = self.encode_asn1_tag_length(0x6C, component)            # Component Portion

        # ---- TCAP END: dtid + dialoguePortion(AARE) + componentPortion -------------
        # DTID
        if orig_transaction_id and 1 <= len(orig_transaction_id) <= 4:
            dtid_value = orig_transaction_id
        else:
            dtid_value = struct.pack('!I', random.randint(0x10000000, 0xFFFFFFFF))
        dtid = self.encode_asn1_tag_length(0x49, dtid_value)

        # Build Dialogue Portion (AARE)
        # dialogue-as-id OID (Q.773 structured dialogue)
        dialogue_as_id_oid = _encode_oid("0.0.17.773.1.1.1")

        # AARE-apdu (APPLICATION 1 -> 0x61)
        # [0] protocol-version BIT STRING -> 80 02 07 80  (version1)
        aare_pv = self.encode_asn1_tag_length(0x80, b"\x07\x80")

        # [1] application-context-name -> EXPLICIT: A1 + inner OID
        # Use shortMsgGatewayContext-v3: 0.4.0.0.1.0.20.3 (MAP SRI-SM)
        acn_inner = _encode_oid("0.4.0.0.1.0.20.3")
        aare_acn = self.encode_asn1_tag_length(0xA1, acn_inner)

        # [2] result -> EXPLICIT: A2 + INTEGER(0)  (accepted)
        # Encodes as: A2 03 02 01 00
        aare_result = self.encode_asn1_tag_length(0xA2, b"\x02\x01\x00")

        # [3] result-source-diagnostic (CHOICE) -> A3 { A1 [1] INTEGER(0) }
        rsd_inner = self.encode_asn1_tag_length(0xA1, b"\x02\x01\x00")
        aare_rsd = self.encode_asn1_tag_length(0xA3, rsd_inner)

        aare_payload = aare_pv + aare_acn + aare_result + aare_rsd
        aare = self.encode_asn1_tag_length(0x61, aare_payload)

        # EXTERNAL: SEQUENCE (0x28) { direct-reference OID, [0] single-ASN1-type (AARE) }
        single_asn1 = self.encode_asn1_tag_length(0xA0, aare)
        external = self.encode_asn1_tag_length(0x28, dialogue_as_id_oid + single_asn1)

        # DialoguePortion: [APPLICATION 11] EXPLICIT -> 0x6B
        dialogue_portion = self.encode_asn1_tag_length(0x6B, external)

        # TCAP END: Tag 0x64 with dtid + dialoguePortion + componentPortion
        tcap_end_data = dtid + dialogue_portion + component_portion
        tcap_end = self.encode_asn1_tag_length(0x64, tcap_end_data)

        # ---- logging ----------------------------------------------------------------
        self.log_debug(f"  TCAP End message created: {len(tcap_end)} bytes")
        self.log_debug(f"  Complete TCAP End: {tcap_end.hex()}")
        self.log_debug(f"  ReturnResultLast content: {rrl_content.hex()}")
        self.log_debug(f"  First bytes should be: 02 01 {invoke_id:02X} 30... (INTEGER invokeID, then SEQUENCE result)")
        self.log_debug("=" * 50)

        return tcap_end

    def decode_bcd_digits(self, bcd_data):
        """Decode BCD encoded digits with detailed logging"""
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
        """Parse SCCP addresses with Wireshark-like logging"""
        addresses = {'called': {}, 'calling': {}}
        self.log_info("parse_sccp_addresses init")
        try:
            if offset + 3 >= len(sccp_data):
                self.log_error("SCCP data too short for address parsing")
                return addresses, offset
            
            ptr_called = sccp_data[offset]
            ptr_calling = sccp_data[offset + 1]
            ptr_data = sccp_data[offset + 2]
            
            self.log_debug(f"SCCP pointer to Called Party address: {ptr_called} (offset + {ptr_called})")
            self.log_debug(f"SCCP pointer to Calling Party address: {ptr_calling} (offset + {ptr_calling})")
            self.log_debug(f"SCCP pointer to Data: {ptr_data} (offset + {ptr_data})")

            # Parse Called Party Address
            called_addr_start = offset + ptr_called
            if called_addr_start < len(sccp_data):
                called_addr_len = sccp_data[called_addr_start]
                self.log_debug(f"Called Party address length byte: {called_addr_len}")
                if called_addr_start + called_addr_len < len(sccp_data):
                    called_addr_data = sccp_data[called_addr_start + 1:called_addr_start + 1 + called_addr_len]

                    if self.log_level == 'DEBUG':
                        self.log_debug(f">> Hex dump of Called Party address ({len(called_addr_data)} bytes): {called_addr_data.hex()}")
                    addresses['called'] = self.parse_single_sccp_address(called_addr_data, "Called Party address")
            
            # Parse Calling Party Address
            calling_addr_start = offset + ptr_calling + 1
            if calling_addr_start < len(sccp_data):
                calling_addr_len = sccp_data[calling_addr_start]
                if calling_addr_start + calling_addr_len < len(sccp_data):
                    calling_addr_data = sccp_data[calling_addr_start + 1 : calling_addr_start + 1 + calling_addr_len]
                    if self.log_level == 'DEBUG':
                        self.log_debug(f">> Hex dump of Calling Party address ({len(calling_addr_data)} bytes): {calling_addr_data.hex()}")
                    addresses['calling'] = self.parse_single_sccp_address(calling_addr_data, "Calling Party address")
            
            data_start = offset + ptr_data
            return addresses, data_start
            
        except Exception as e:
            self.log_error(f"Error parsing SCCP addresses: {e}")
            return addresses, offset
    
    def parse_single_sccp_address(self, addr_data, addr_type):
        """Parse a single SCCP address with Wireshark-like logging"""
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
            
            if self.log_level == 'DEBUG':
                self.log_debug(f"{addr_type} ({len(addr_data)} bytes)")
                self.log_debug(f"    Address Indicator")
                self.log_debug(f"        {ai:08b} = Address Indicator")
                self.log_debug(f"        0... .... = Reserved for national use: 0x{(ai >> 7) & 0x01}")
                self.log_debug(f"        .{(0 if route_on_gt else 1)}.. .... = Routing Indicator: {'Route on GT' if route_on_gt else 'Route on PC/SSN'} (0x{(ai >> 6) & 0x01})")
                self.log_debug(f"        ..{gti:04b} = Global Title Indicator: {'Translation Type, Numbering Plan, Encoding Scheme, and Nature of Address Indicator included' if gti == 4 else 'Other'} (0x{gti})")
                self.log_debug(f"        .... ..{1 if ssn_present else 0}. = SubSystem Number Indicator: {'SSN present' if ssn_present else 'SSN not present'} (0x{(ai >> 1) & 0x01})")
                self.log_debug(f"        .... ...{1 if pc_present else 0} = Point Code Indicator: {'Point Code present' if pc_present else 'Point Code not present'} (0x{ai & 0x01})")
            
            offset = 1
            
            if pc_present:
                if offset + 2 <= len(addr_data):
                    pc = struct.unpack('<H', addr_data[offset:offset+2])[0]
                    address['pc'] = pc
                    if self.log_level == 'DEBUG':
                        self.log_debug(f"    Point Code: {pc} (0x{pc:04X})")
                    offset += 2
            
            if ssn_present:
                if offset < len(addr_data):
                    ssn = addr_data[offset]
                    address['ssn'] = ssn
                    if self.log_level == 'DEBUG':
                        ssn_name = {6: 'HLR (Home Location Register)', 8: 'MSC (Mobile Switching Center)'}.get(ssn, f'Unknown ({ssn})')
                        self.log_debug(f"    SubSystem Number: {ssn_name} ({ssn})")
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
                    
                    if self.log_level == 'DEBUG':
                        self.log_debug(f"    Global Title 0x4 ({len(gt_data)} bytes)")
                        self.log_debug(f"        Translation Type: 0x{tt:02X}")
                        self.log_debug(f"        {np:04b} .... = Numbering Plan: {'ISDN/telephony' if np == 1 else 'Unknown'} (0x{np})")
                        self.log_debug(f"        .... {es:04b} = Encoding Scheme: {'BCD, odd number of digits' if es == 1 else 'BCD, even number of digits' if es == 2 else 'Unknown'} (0x{es})")
                        self.log_debug(f"        Nature of Address Indicator: {'International number' if nai == 4 else 'Unknown'} (0x{nai:02X})")
                        self.log_debug(f"        {addr_type.split()[0]} Party Digits: {digits}")
                        self.log_debug(f"            Called or Calling GT Digits: {digits}")
                        self.log_debug(f"            Number of {addr_type.split()[0]} Party Digits: {len(digits)}")
                        if digits.startswith('61'):
                            self.log_debug(f"            Country Code: Australia (61)")
        
        except Exception as e:
            self.log_error(f"Error parsing {addr_type}: {e}")
            
        return address


    def parse_tcap_message(self, tcap_data):
        """
        Parse TCAP message and extract:
          - transaction_id (OTID for BEGIN, DTID for END)
          - invoke_id
          - op_code (MAP operation code, int for localValue; or tuple ('oid', 'x.y.z...') for globalValue)
          - msisdn (if present in parameters)
          - original tcap_data (unchanged)
        Returns: (transaction_id: bytes|None, invoke_id: int|None, op_code: int|('oid', str)|None, msisdn: str|None, tcap_data: bytes)
        """

        # ---- helpers (local scope) ---------------------------------------------
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
                return l, off + n  # (length, next_off_value)
            else:
                return first, off  # short form (len, next_off_value)

        def _read_tlv(buf, off):
            """Return (tag, length, val_start, val_end, next_tlv_off) or None on error."""
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
            """Decode OID bytes -> dotted string (best-effort)."""
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

        # ---- start parsing ------------------------------------------------------
        try:
            self.log_info("PCA parse_tcap_message init")
            if len(tcap_data) < 2:
                self.log_error("Transaction Capabilities Application Part")
                self.log_error(" [Error: TCAP data too short]")
                return None, None, None, None, tcap_data

            # Top-level TCAP TLV: BEGIN(0x62) / END(0x64) / CONTINUE(0x65) / ABORT(0x67)
            top = _read_tlv(tcap_data, 0)
            if top is None:
                self.log_error("Invalid TCAP top-level TLV")
                return None, None, None, None, tcap_data

            tcap_tag, tcap_len, tcap_vs, tcap_ve, _ = top
            tcap_type = {0x62: 'begin', 0x64: 'end', 0x65: 'continue', 0x67: 'abort'}.get(tcap_tag, 'Unknown')
            if self.log_level == 'DEBUG':
                self.log_debug("Transaction Capabilities Application Part")
                self.log_debug(f" {tcap_type}")
                self.log_debug(f" Tag: 0x{tcap_tag:02X} Length: {tcap_len}")

            transaction_id = None
            component_portion_slice = None

            # Walk children inside the top-level value to pick up TIDs, Dialogue, Component Portion
            off = tcap_vs
            while off < tcap_ve:
                node = _read_tlv(tcap_data, off)
                if node is None:
                    break
                tag, length, vs, ve, off = node

                if tag in (0x48, 0x49):  # 0x48 = otid (BEGIN), 0x49 = dtid (END)
                    transaction_id = tcap_data[vs:ve]
                    if self.log_level == 'DEBUG':
                        which = 'otid' if tag == 0x48 else 'dtid'
                        self.log_debug(f" {which}: {transaction_id.hex()}")

                elif tag == 0x6C:  # Component Portion
                    component_portion_slice = (vs, ve)

                # 0x6B is Dialogue Portion (AARQ/AARE) — not required for op_code

            invoke_id = None
            op_code = None

            # Parse Component Portion -> first component
            if component_portion_slice:
                cp_vs, cp_ve = component_portion_slice

                # ComponentPortion value is SEQUENCE OF components (concatenated TLVs)
                c_off = cp_vs
                while c_off < cp_ve:
                    comp = _read_tlv(tcap_data, c_off)
                    if comp is None:
                        break
                    c_tag, c_len, c_vs, c_ve, c_off = comp

                    # Component choices per Q.773: A1=Invoke, A2=ReturnResultLast, A3=ReturnError, A4=Reject
                    if c_tag in (0xA1, 0xA2, 0xA3, 0xA4):
                        inner_off = c_vs

                        # 1) First element commonly INTEGER invokeID
                        first = _read_tlv(tcap_data, inner_off)
                        if first:
                            f_tag, f_len, f_vs, f_ve, inner_off = first
                            if f_tag == 0x02:  # INTEGER
                                try:
                                    invoke_id = int.from_bytes(tcap_data[f_vs:f_ve], "big")
                                    if self.log_level == 'DEBUG':
                                        self.log_debug(f" invokeID: {invoke_id}")
                                except Exception:
                                    pass

                        # 2) Extract op_code depending on component
                        if c_tag == 0xA1:
                            # Invoke ::= SEQUENCE { invokeID, [linked], opCode (CHOICE), parameter OPTIONAL, ... }
                            scan = inner_off
                            while scan < c_ve and op_code is None:
                                tlv = _read_tlv(tcap_data, scan)
                                if tlv is None:
                                    break
                                s_tag, s_len, s_vs, s_ve, scan = tlv

                                # opCode CHOICE: [0] localValue INTEGER  -> tag 0x80 (primitive)
                                if s_tag == 0x80:
                                    op_code = int.from_bytes(tcap_data[s_vs:s_ve], "big")

                                # opCode CHOICE: [1] globalValue OBJECT IDENTIFIER
                                elif s_tag == 0x06:
                                    op_code = ('oid', _decode_oid(tcap_data[s_vs:s_ve]))

                                # Some encoders use EXPLICIT for [1]
                                elif s_tag == 0xA1:
                                    inner2 = _read_tlv(tcap_data, s_vs)
                                    if inner2 and inner2[0] == 0x06:
                                        _, _, i_vs, i_ve, _ = inner2
                                        op_code = ('oid', _decode_oid(tcap_data[i_vs:i_ve]))

                                # Some encoders use EXPLICIT [0] (A0) wrapping INTEGER
                                elif s_tag == 0xA0:
                                    inner2 = _read_tlv(tcap_data, s_vs)
                                    if inner2 and inner2[0] in (0x80, 0x02):
                                        _, _, i_vs, i_ve, _ = inner2
                                        op_code = int.from_bytes(tcap_data[i_vs:i_ve], "big")

                                # Fallback tolerance: occasionally op code leaks as universal INTEGER
                                elif s_tag == 0x02 and s_len <= 2 and op_code is None:
                                    val = int.from_bytes(tcap_data[s_vs:s_ve], "big")
                                    if 1 <= val <= 255:
                                        op_code = val

                        elif c_tag == 0xA2:
                            # ReturnResultLast ::= SEQUENCE {
                            #   invokeID,
                            #   result ::= SEQUENCE { opCode, parameter }
                            # }
                            res = _read_tlv(tcap_data, inner_off)
                            if res and res[0] == 0x30:  # SEQUENCE
                                _, _, r_vs, r_ve, _ = res
                                r_off = r_vs

                                # opCode is the first element inside 'result'
                                op = _read_tlv(tcap_data, r_off)
                                if op:
                                    o_tag, o_len, o_vs, o_ve, _ = op

                                    # [0] localValue INTEGER
                                    if o_tag == 0x80:
                                        op_code = int.from_bytes(tcap_data[o_vs:o_ve], "big")

                                    # EXPLICIT [0] wrapper (A0) containing INTEGER (0x02) or 0x80
                                    elif o_tag == 0xA0:
                                        inner3 = _read_tlv(tcap_data, o_vs)
                                        if inner3:
                                            i_tag, _, i_vs, i_ve, _ = inner3
                                            if i_tag in (0x80, 0x02):
                                                op_code = int.from_bytes(tcap_data[i_vs:i_ve], "big")

                                    # Tolerate universal INTEGER as opCode (non‑standard but seen)
                                    elif o_tag == 0x02:
                                        op_code = int.from_bytes(tcap_data[o_vs:o_ve], "big")

                                    # [1] globalValue OBJECT IDENTIFIER
                                    elif o_tag == 0x06:
                                        op_code = ('oid', _decode_oid(tcap_data[o_vs:o_ve]))

                                    elif o_tag == 0xA1:
                                        inner4 = _read_tlv(tcap_data, o_vs)
                                        if inner4 and inner4[0] == 0x06:
                                            _, _, i_vs, i_ve, _ = inner4
                                            op_code = ('oid', _decode_oid(tcap_data[i_vs:i_ve]))

                        # Only the first component is considered for request parsing
                        break

            # Reuse your existing MSISDN finder (kept as-is)
            msisdn = self.extract_msisdn_from_tcap(tcap_data)

            if self.log_level == 'DEBUG':
                self.log_debug(f" Parsed op_code: {op_code}")
            return transaction_id, invoke_id, op_code, msisdn, tcap_data

        except Exception as e:
            self.log_error(f"Error parsing TCAP message (op_code extraction): {e}")
            return None, None, None, None, tcap_data
  

    def extract_msisdn_from_tcap(self, tcap_data):
        """Extract MSISDN from TCAP data with Wireshark-like logging"""
        msisdn = None
        
        self.log_debug("Searching for MSISDN in TCAP data...")
        
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
                                if self.log_level == 'DEBUG':
                                    self.log_debug("GSM Mobile Application")
                                    self.log_debug(f"    Component: invoke (1)")
                                    self.log_debug(f"        invoke")
                                    self.log_debug(f"            msisdn: {potential_data.hex()}")
                                    self.log_debug(f"                1... .... = Extension: No Extension")
                                    self.log_debug(f"                .001 .... = Nature of number: International Number (0x1)")
                                    self.log_debug(f"                .... 0001 = Number plan: ISDN/Telephony Numbering (Rec ITU-T E.164) (0x1)")
                                    self.log_debug(f"                E.164 number (MSISDN): {msisdn}")
                                    if msisdn.startswith('61'):
                                        self.log_debug(f"                    Country Code: Australia (61)")
                                return msisdn
        
        if not msisdn:
            #msisdn = CONFIG['remote_gt']
            #self.log_debug(f"MSISDN not found in TCAP data, using configured remote GT: {msisdn}")
            self.log_debug(f"MSISDN not found in TCAP data - request maybe MT-FSM")
        
        return msisdn

    def create_sccp_response(self, calling_addr, called_addr, tcap_data):
        """Create SCCP XUDT response with proper data parameter length byte"""
        try:
            sccp_type = SCCP_XUDT
            protocol_class = 0x80
            hop_counter = 0x0F

            # Build addresses for the response (swap direction)
            response_called = SCCPAddress(
                gt=calling_addr.get('gt') or CONFIG.get('remote_gt'),
                ssn=8
            )
            response_calling = SCCPAddress(
                gt=CONFIG['hlr_gt'],
                ssn=6
            )

            self.log_debug("Creating SCCP response addresses")
            called_addr_data = response_called.pack()
            calling_addr_data = response_calling.pack()

            if len(called_addr_data) == 0 or len(calling_addr_data) == 0:
                self.log_error("Empty SCCP address encoding detected")
                return None

            # Sanity: first byte is content length (LEN1); on-wire size = 1 + LEN1
            assert called_addr_data[0] + 1 == len(called_addr_data), "Called length mismatch"
            assert calling_addr_data[0] + 1 == len(calling_addr_data), "Calling length mismatch"

            # Calculate pointers
            ptr1 = 4
            ptr2 = ptr1 + called_addr_data[0]      
            ptr3 = ptr2 + calling_addr_data[0]    
            ptr4 = 0

            # Build SCCP header
            sccp_header = struct.pack('!BBBBBBB', sccp_type, protocol_class, hop_counter, ptr1, ptr2, ptr3, ptr4)
            
            # CRITICAL FIX: Data parameter of XUDT needs length byte
            data_len = len(tcap_data)
            sccp_data = (
                sccp_header +
                called_addr_data +
                calling_addr_data +
                struct.pack('!B', data_len) +   # Length byte for data parameter
                tcap_data                       # TCAP bytes (start with 0x64)
            )

            if self.log_level == 'DEBUG':
                self.parse_sccp_response(sccp_data, "Outgoing SCCP Response")
                self.log_debug("Outgoing SCCP Response Hex: {}".format(sccp_data.hex()))
                self.log_debug(f"SCCP pointers : p1=0x{ptr1:02X} p2=0x{ptr2:02X} p3=0x{ptr3:02X} p4=0x{ptr4:02X}")

            return sccp_data

        except Exception as e:
            self.log_error(f"Error creating SCCP response: {e}")
            return None
    
    def create_m3ua_data_message(self, dest_pc, orig_pc, sccp_data, si=None, ni=None, mp=0, sls=None):
        """Create M3UA DATA message with Wireshark-like logging"""
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
            
            if self.log_level == 'DEBUG':
                self.parse_and_log_response(m3ua_msg.pack(), "Outgoing M3UA DATA")
                self.log_debug("Outgoing M3UA DATA Hex: {}".format(m3ua_msg.pack().hex()))
            return m3ua_msg
            
        except Exception as e:
            self.log_error(f"Error creating M3UA DATA message: {e}")
            return None
    
    def parse_and_log_response(self, response_data, msg_type):
        """Parse and log PDU with Wireshark-like format for M3UA, SCCP, TCAP, and MAP"""
        try:
            if self.log_level == 'DEBUG':
                self.log_debug(f"\n{'=' * 60}\n{msg_type} ({len(response_data)} bytes)\n{'=' * 60}")
            
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
            
            if self.log_level == 'DEBUG':
                self.log_debug("MTP 3 User Adaptation Layer")
                self.log_debug(f"    Version: Release {version} ({version})")
                self.log_debug(f"    Reserved: 0x{reserved:02X}")
                self.log_debug(f"    Message class: {msg_class_name} ({msg_class})")
                self.log_debug(f"    Message Type: {msg_type_name} ({msg_type_val})")
                self.log_debug(f"    Message length: {msg_length}")
            
            offset = 8
            param_num = 1
            
            while offset < len(response_data):
                if offset + 4 > len(response_data):
                    self.log_error("    [Error: Incomplete parameter at offset {offset}]")
                    break
                    
                tag, length = struct.unpack('!HH', response_data[offset:offset+4])
                param_data = response_data[offset+4:offset+length] if length > 4 else b''
                param_name = self.get_m3ua_param_name(tag)
                
                if self.log_level == 'DEBUG':
                    self.log_debug(f"    {param_name} ({1 if tag == M3UA_PARAM_ROUTING_CONTEXT else len(param_data)} {'context' if tag == M3UA_PARAM_ROUTING_CONTEXT else 'bytes'})")
                    self.log_debug(f"        Parameter Tag: {param_name} ({tag})")
                    self.log_debug(f"        Parameter length: {length}")
                
                if tag == M3UA_PARAM_ROUTING_CONTEXT:
                    if len(param_data) >= 4:
                        rc_value = struct.unpack('!I', param_data[:4])[0]
                        if self.log_level == 'DEBUG':
                            self.log_debug(f"        Routing context: {rc_value}")
                
                elif tag == M3UA_PARAM_PROTOCOL_DATA:
                    self.parse_protocol_data_response(param_data)
                
                padded_length = (length + 3) & ~3
                offset += padded_length
                param_num += 1
            
        except Exception as e:
            self.log_error(f"Error parsing {msg_type}: {e}")

    def parse_protocol_data_response(self, protocol_data):
        """Parse Protocol Data parameter with Wireshark-like logging"""
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
            
            if self.log_level == 'DEBUG':
                self.log_debug(f"    Protocol data (SS7 message of {len(protocol_data) - 12} bytes)")
                self.log_debug(f"        Parameter Tag: Protocol data ({M3UA_PARAM_PROTOCOL_DATA})")
                self.log_debug(f"        Parameter length: {len(protocol_data) + 4}")
                self.log_debug(f"        OPC: {opc} (0x{opc:04X})")
                self.log_debug(f"        DPC: {dpc} (0x{dpc:04X})")
                self.log_debug(f"        SI: SCCP ({si})")
                self.log_debug(f"        NI: {'National network' if ni == 2 else 'International network'} ({ni})")
                self.log_debug(f"        MP: {mp}")
                self.log_debug(f"        SLS: {sls}")
                self.log_debug(f"        [MTP3 equivalents]")
                self.log_debug(f"            [OPC: {opc}]")
                self.log_debug(f"            [DPC: {dpc}]")
                self.log_debug(f"            [PC: {opc}]")
                self.log_debug(f"            [PC: {dpc}]")
                self.log_debug(f"            [NI: {ni}]")
                self.log_debug(f"            [SLS: {sls}]")
                if len(protocol_data) % 4 != 0:
                    self.log_debug(f"        Padding: {'0' * (4 - (len(protocol_data) % 4))}")
            
            if len(protocol_data) > 12:
                sccp_data = protocol_data[12:]
                self.parse_sccp_response(sccp_data, "SCCP Data")
                
        except Exception as e:
            self.log_error(f"Error parsing protocol data: {e}")

    def parse_sccp_response(self, sccp_data, context):
        """Parse SCCP response with Wireshark-like logging"""
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
            
            if self.log_level == 'DEBUG':
                self.log_debug(f"Signalling Connection Control Part")
                hex_lines = ' '.join(f"{b:02X}" for b in sccp_data)
                self.log_debug(f">> Hex dump of SCCP data ({len(sccp_data)} bytes): {hex_lines}")
                self.log_debug(f"    Message Type: {sccp_type_name} (0x{sccp_type:02X})")
                self.log_debug(f"    {(protocol_class & 0x0F):04b} .... = Class: 0x{(protocol_class & 0x0F):X}")
                self.log_debug(f"    {(protocol_class >> 4):04b} .... = Message handling: {'Return message on error' if (protocol_class >> 4) == 8 else 'Unknown'} (0x{(protocol_class >> 4):X})")
                self.log_debug(f"    Hop Counter: 0x{hop_counter:02X}")
                self.log_debug(f"    Pointer to first Mandatory Variable parameter: {ptr1}")
                self.log_debug(f"    Pointer to second Mandatory Variable parameter: {ptr2}")
                self.log_debug(f"    Pointer to third Mandatory Variable parameter: {ptr3}")
                self.log_debug(f"    Pointer to Optional parameter: {ptr4}")
            
            addresses, tcap_offset = self.parse_sccp_addresses(sccp_data, 3)
            
            if tcap_offset < len(sccp_data):
                tcap_data = sccp_data[tcap_offset+3:]
                self.parse_tcap_response(tcap_data)
                
        except Exception as e:
            self.log_error(f"Error parsing {context}: {e}")

    def parse_tcap_response(self, tcap_data):
        """Parse TCAP response with Wireshark-like logging"""
        try:
            if len(tcap_data) < 2:
                self.log_error("Transaction Capabilities Application Part")
                self.log_error("    [Error: TCAP data too short]")
                return
                
            tcap_tag = tcap_data[0]
            tcap_len = tcap_data[1]
            tcap_type = {TCAP_BEGIN: 'begin', TCAP_END: 'end', TCAP_CONTINUE: 'continue', TCAP_ABORT: 'abort'}.get(tcap_tag, 'Unknown')
            
            if self.log_level == 'DEBUG':
                self.log_debug("Transaction Capabilities Application Part")
                self.log_debug(f"    {tcap_type}")
                self.log_debug(f"        [Transaction Id: {tcap_data[4:8].hex() if len(tcap_data) >= 8 else 'N/A'}]")
            
            transaction_id = None
            for i in range(len(tcap_data) - 4):
                if tcap_data[i] == 0x49:  # DTID for END
                    tid_len = tcap_data[i + 1]
                    if tid_len <= 4 and i + 2 + tid_len <= len(tcap_data):
                        transaction_id = tcap_data[i + 2:i + 2 + tid_len]
                        if self.log_level == 'DEBUG':
                            self.log_debug(f"        Destination Transaction ID")
                            self.log_debug(f"            dtid: {transaction_id.hex()}")
                        break
            
            offset = 2
            while offset < len(tcap_data):
                if tcap_data[offset] == 0xA2:  # ReturnResultLast
                    comp_len = tcap_data[offset + 1]
                    if offset + 2 + comp_len <= len(tcap_data):
                        comp_data = tcap_data[offset + 2:offset + 2 + comp_len]
                        if self.log_level == 'DEBUG':
                            self.log_debug(f"        Component: ReturnResultLast (2)")
                            self.log_debug(f"            returnResultLast")
                       
                    break
                offset += 1
                
        except Exception as e:
            self.log_error(f"Error parsing TCAP response: {e}")
            

    def parse_map_sri_sm_response(self, param_data):
        """Parse MAP SRI-SM response parameters with Wireshark-like logging"""
        try:
            if self.log_level == 'DEBUG':
                self.log_debug("GSM Mobile Application")
                self.log_debug(f"    Component: ReturnResultLast (2)")
                self.log_debug(f"        returnResultLast")
            
            offset = 0
            while offset < len(param_data):
                tag = param_data[offset]
                length = param_data[offset + 1]
                value = param_data[offset + 2:offset + 2 + length]
               
                if tag == ASN1_OCTET_STRING:
                    digits = self.decode_bcd_digits(value)
                    if self.log_level == 'DEBUG':
                        self.log_debug(f" imsi (TBCD): {value.hex()}")
                        self.log_debug(f" IMSI: {digits}")
                        self.log_debug(f"            imsi: {value.hex()}")
                        self.log_debug(f"                1... .... = Extension: No Extension")
                        self.log_debug(f"                .001 .... = Nature of number: International Number (0x1)")
                        self.log_debug(f"                .... 0001 = Number plan: ISDN/Telephony Numbering (Rec ITU-T E.164) (0x1)")
                        self.log_debug(f"                E.164 number (IMSI): {digits}")
                        if digits.startswith('61'):
                            self.log_debug(f"                    Country Code: Australia (61)")
                
                elif tag == 0xA1:
                    if self.log_level == 'DEBUG':
                        self.log_debug(f"            locationInfoWithLMSI")
                    inner_offset = 0
                    while inner_offset < len(value):
                        inner_tag = value[inner_offset]
                        inner_len = value[inner_offset + 1]
                        inner_value = value[inner_offset + 2:inner_offset + 2 + inner_len]
                        
                        if inner_tag == ASN1_CONTEXT_0 and inner_value[0] == 0x91:
                            digits = self.decode_bcd_digits(inner_value[1:])
                            if self.log_level == 'DEBUG':
                                self.log_debug(f"                networkNode-Number: {inner_value.hex()}")
                                self.log_debug(f"                    1... .... = Extension: No Extension")
                                self.log_debug(f"                    .001 .... = Nature of number: International Number (0x1)")
                                self.log_debug(f"                    .... 0001 = Number plan: ISDN/Telephony Numbering (Rec ITU-T E.164) (0x1)")
                                self.log_debug(f"                    E.164 number (NNN): {digits}")
                                if digits.startswith('61'):
                                    self.log_debug(f"                        Country Code: Australia (61)")
                        
                        elif inner_tag == ASN1_CONTEXT_1:
                            lmsi = struct.unpack('!I', inner_value)[0]
                            if self.log_level == 'DEBUG':
                                self.log_debug(f"                lmsi: 0x{lmsi:08X}")
                        
                        inner_offset += 2 + inner_len
                
                offset += 2 + length
                
        except Exception as e:
            self.log_error(f"Error parsing MAP SRI-SM response: {e}")

    def parse_m3ua_data(self, m3ua_msg, conn, addr):
        """Parse incoming M3UA DATA message with Wireshark-like logging"""
        try:
          
            self.log_info("=" * 60)
            self.log_info(f"Incoming M3UA DATA from {addr[0]}:{addr[1]}")
            self.log_info("=" * 60)
            
            raw = m3ua_msg.pack()
            if len(raw) < 8:
                self.log_error("MTP 3 User Adaptation Layer")
                self.log_error("    [Error: Message too short for M3UA header]")
                return
            
            version, reserved, msg_class, msg_type, msg_length = struct.unpack('!BBBBI', raw[:8])
            msg_class_name = {M3UA_TRANSFER_CLASS: 'Transfer messages'}.get(msg_class, f'Unknown ({msg_class})')
            msg_type_name = {M3UA_DATA: 'Payload data (DATA)'}.get(msg_type, f'Unknown ({msg_type})')
            
            if self.log_level == 'DEBUG':
                self.log_debug("MTP 3 User Adaptation Layer")
                self.log_debug(f"    Version: Release {version} ({version})")
                self.log_debug(f"    Reserved: 0x{reserved:02X}")
                self.log_debug(f"    Message class: {msg_class_name} ({msg_class})")
                self.log_debug(f"    Message Type: {msg_type_name} ({msg_type})")
                self.log_debug(f"    Message length: {msg_length}")
            
            offset = 8
            protocol_data = None
            routing_context = None
            
            while offset < len(raw):
                tag, length = struct.unpack('!HH', raw[offset:offset+4])
                param_data = raw[offset+4:offset+length] if length > 4 else b''
                param_name = self.get_m3ua_param_name(tag)
                
                if self.log_level == 'DEBUG':
                    self.log_debug(f"    {param_name} ({1 if tag == M3UA_PARAM_ROUTING_CONTEXT else len(param_data)} {'context' if tag == M3UA_PARAM_ROUTING_CONTEXT else 'bytes'})")
                    self.log_debug(f"        Parameter Tag: {param_name} ({tag})")
                    self.log_debug(f"        Parameter length: {length}")
                
                if tag == M3UA_PARAM_ROUTING_CONTEXT:
                    if len(param_data) >= 4:
                        routing_context = struct.unpack('!I', param_data[:4])[0]
                        if self.log_level == 'DEBUG':
                            self.log_debug(f"        Routing context: {routing_context}")
                
                elif tag == M3UA_PARAM_PROTOCOL_DATA:
                    protocol_data = param_data
                    ##self.parse_protocol_data_response(protocol_data)
                
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
            if self.log_level == 'DEBUG':
                self.log_debug("=" * 60)

    def get_m3ua_param_name(self, tag):
        """Get M3UA parameter name from tag"""
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
        """Handle M3UA protocol messages"""
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
            
                if self.log_level == 'DEBUG':
                    self.log_info(f"M3UA HEARTBEAT received from {addr[0]}:{addr[1]}")
                response = self.create_m3ua_response(M3UA_ASPSM_CLASS, M3UA_BEAT)
                if response:
                    conn.send(response.pack())
                    
                    if self.log_level == 'DEBUG':

                        self.log_info(f"M3UA HEARTBEAT-ACK sent to {addr[0]}:{addr[1]}")
        
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
        """Handle M3UA DATA message with strict spec-based parsing"""
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

    def handle_sccp_udt(self, sccp_data, orig_pc, dest_pc, conn, addr):
        """Handle SCCP UDT message"""
        try:
            if len(sccp_data) < 5:
                self.log_error("SCCP UDT data too short")
                return
                
            protocol_class = sccp_data[1]
            addresses, tcap_offset = self.parse_sccp_addresses(sccp_data, 3)
            
            if tcap_offset < len(sccp_data):
                tcap_data = sccp_data[tcap_offset+3:]
               

                transaction_id, invoke_id, op_code, msisdn, _ = self.parse_tcap_message(tcap_data)


               
                if invoke_id is not None and isinstance(op_code, int):
                    if op_code == MAP_SRI_SM and msisdn:
                      op_code_description = "sendRoutingInfoForSM"
                      self.log_info(f"Incomig request : {op_code_description}  ")
                      self.log_info(f"--------------------  Prepare SRI-SM Response -------------------------  ")
                      response_tcap = self.create_sri_sm_response(invoke_id, msisdn, transaction_id)
                      sccp_response = self.create_sccp_response(addresses['calling'], addresses['called'], response_tcap) 
                  
                      
                    elif op_code == MAP_MT_FSM:
                      op_code_description = "mt-forwardSM"
                      self.log_info(f"Incomig request : {op_code_description}  ")
                      self.log_info(f"--------------------  Prepare MT-FSM Response -------------------------  ")
                      response_tcap = self.create_mt_fsm_response(invoke_id, op_code, transaction_id)
                      sccp_response = self.create_sccp_response(addresses['calling'], addresses['called'], response_tcap) 
                      
                      
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
                                    #self.log_info(f"✓ Successfully sent SRI-SM Response: {bytes_sent}/{len(response_data)} bytes")
                                    self.log_info(f"{CONFIG['local_pc']} → {CONFIG['remote_pc']} GSM MAP 232 SACK returnResultLast {op_code_description}")


                                else:
                                    self.log_error(f"✗ Partial send: {bytes_sent}/{len(response_data)} bytes")
                            except Exception as e:
                                self.log_error(f"✗ Failed to send response: {e}")
                        else:
                            self.log_error("Failed to create M3UA response")
                    else:
                        self.log_error("Failed to create SCCP response")
                 

                else:
                    self.log_error("Could not extract invoke_id or MSISDN from TCAP message")
            else:
                self.log_error("No TCAP data found in SCCP UDT")
                
        except Exception as e:
            self.log_error(f"Error handling SCCP UDT: {e}")

    def handle_client(self, conn, addr):
        """Handle client connection"""
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
    
    def start(self):
        """Start the enhanced MAP SIGTRAN server"""
        try:
            if not self.check_sctp_support():
                return
            
            self.socket = self.create_socket()
            if not self.socket:
                return
            
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            
            if self.log_level in ['INFO', 'DEBUG']:
                self.log_info("=" * 60)
                self.log_info(f"Enhanced MAP SIGTRAN Server listening on {self.host}:{self.port}")
                self.log_info("Features:")
                self.log_info("  - MAP SRI-SM request handling")
                self.log_info("  - SRI-SM response with NNN and IMSI")
                self.log_info("  - Wireshark-like PDU logging")
                self.log_info("  - M3UA/SCCP/TCAP/MAP stack support")
                self.log_info("=" * 60)
            
            self.running = True
            
            while self.running:
                try:
                    conn, addr = self.socket.accept()
                    self.log_info(f"New SCTP connection from {addr[0]}:{addr[1]}")
                    
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr)
                    )
                    client_thread.daemon = True
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
        """Stop the server"""
        self.log_info("Stopping Enhanced MAP SIGTRAN server...")
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
    
    def cleanup(self):
        """Clean up resources"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.log_info("Enhanced MAP SIGTRAN server stopped")

def main():
    """Main function with enhanced startup information and log level configuration"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced MAP SIGTRAN Server with configurable logging')
    parser.add_argument('--log-level', choices=['ERROR', 'INFO', 'DEBUG'], default='INFO',
                       help='Set logging level (ERROR: only errors, INFO: basic info + M3UA messages, DEBUG: detailed protocol traces)')
    parser.add_argument('--port', type=int, default=2905, help='Server port (default: 2905)')
    args = parser.parse_args()
    
    # Update config with log level
    CONFIG['log_level'] = args.log_level
    
    if args.log_level in ['INFO', 'DEBUG']:
        print("=" * 60)
        print("Enhanced MAP SIGTRAN Server with SRI-SM Support")
        print("Handles Send Routing Info for Short Message requests")
        print("Responds with Network Node Number (NNN) and IMSI")
        print("Logs PDUs in Wireshark-like format")
        print("=" * 60)
        print()
        print("Starting Enhanced MAP SIGTRAN Server...")
        print("Configuration:")
        print(f"  Local GT (HLR): {CONFIG['local_gt']}")
        print(f"  Local PC: {CONFIG['local_pc']}")
        print(f"  Remote GT: {CONFIG['remote_gt']}")
        print(f"  Remote PC: {CONFIG['remote_pc']}")
        print(f"  Route Context: {CONFIG['route_context']}")
        print(f"  MSC GT (NNN): {CONFIG['msc_gt']}")
        print(f"  VLR GT: {CONFIG['vlr_gt']}")
        print(f"  Log Level: {args.log_level}")
        print()
        print("Features:")
        print("  ✓ Enhanced MSISDN parsing from TCAP")
        print("  ✓ Proper ASN.1 encoding for MAP responses")
        print("  ✓ IMSI generation based on MSISDN")
        print("  ✓ Wireshark-like logging for M3UA/SCCP/TCAP/MAP")
        print("  ✓ Error handling and troubleshooting support")
        print("  ✓ Configurable log levels (ERROR/INFO/DEBUG)")
        print()
        print("Logs are written to: map_sigtran_server.log")
        print("Press Ctrl+C to stop")
        print("=" * 60)
        print()
    
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
            print(f"Fatal error: {e}")  # Always show fatal errors
        server.stop()

if __name__ == "__main__":
    main()
