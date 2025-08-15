#!/usr/bin/env python3
"""
SIGTRAN Server with MAP SRI-SM Support
Handles MAP Send Routing Info for Short Message requests
Supports M3UA/SCCP/TCAP/MAP protocol stack
Requires root privileges for native SCTP
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

# Configuration
CONFIG = {
    'local_gt': '61418079999',
    'local_pc': 6199,
    'remote_gt': '61418706002', 
    'remote_pc': 12092,
    'route_context': 12092,
    'ssn': 6,  # HLR SSN
    'network_indicator': 2,  # International network
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
SCCP_AI_GT_PRESENT = 0x04
SCCP_AI_PC_PRESENT = 0x01
SCCP_AI_SSN_PRESENT = 0x02
SCCP_AI_ROUTING_GT = 0x40

# TCAP Message Types
TCAP_BEGIN = 0x62
TCAP_CONTINUE = 0x65
TCAP_END = 0x64
TCAP_ABORT = 0x67

# MAP Operation Codes
MAP_SRI_SM = 45        # Send Routing Info for SM
MAP_SRI_SM_RESP = 45   # Same opcode for response

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
        print(f"DEBUG: M3UAParameter.unpack tag=0x{tag:04X}, length={length}")
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
        # Address Indicator
        ai = 0
        if self.gt:
            ai |= SCCP_AI_GT_PRESENT | SCCP_AI_ROUTING_GT
        if self.pc is not None:
            ai |= SCCP_AI_PC_PRESENT
        if self.ssn is not None:
            ai |= SCCP_AI_SSN_PRESENT
        
        addr_data = struct.pack('!B', ai)
        
        # Point Code (if present)
        if self.pc is not None:
            addr_data += struct.pack('!H', self.pc)
        
        # SSN (if present)
        if self.ssn is not None:
            addr_data += struct.pack('!B', self.ssn)
        
        # Global Title (if present)
        if self.gt:
            # GT Type 4 (Nature of Address + Numbering Plan + Translation Type + Encoding Scheme)
            gt_data = struct.pack('!BBB', 0x00, 0x12, 0x01)  # TT=0, NP=ISDN/E164, NOA=International
            
            # Encode GT digits (BCD)
            gt_digits = self.gt
            if len(gt_digits) % 2:
                gt_digits += 'F'  # Pad with F if odd length
            
            for i in range(0, len(gt_digits), 2):
                d1 = int(gt_digits[i+1] if i+1 < len(self.gt) else 15)
                d2 = int(gt_digits[i])
                gt_data += struct.pack('!B', (d1 << 4) | d2)
            
            addr_data += gt_data
        
        # Length byte at the beginning
        return struct.pack('!B', len(addr_data)) + addr_data

class MAPSIGTRANServer:
    """SIGTRAN Server with MAP SRI-SM Support"""
    
    def __init__(self, host='0.0.0.0', port=2915):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.asp_states = {}
        self.transaction_id = 1
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.logger = logging.getLogger('MAPSIGTRANServer')
        
        # Check root privileges
        if os.geteuid() != 0:
            self.logger.error("This server requires root privileges for native SCTP!")
            self.logger.error("Please run with: sudo python3 " + sys.argv[0])
            sys.exit(1)
        
        self.logger.info(f"Configuration:")
        self.logger.info(f"  Local GT: {CONFIG['local_gt']}, PC: {CONFIG['local_pc']}")
        self.logger.info(f"  Remote GT: {CONFIG['remote_gt']}, PC: {CONFIG['remote_pc']}")
        self.logger.info(f"  Route Context: {CONFIG['route_context']}")
    
    def check_sctp_support(self):
        """Check if kernel supports SCTP"""
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_SCTP)
            test_sock.close()
            return True
        except (OSError, socket.error) as e:
            self.logger.error(f"SCTP not supported: {e}")
            self.logger.error("Install SCTP support: sudo apt-get install libsctp-dev")
            return False
    
    def create_socket(self):
        """Create SCTP socket"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_SCTP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.logger.info("Created native SCTP socket")
            return sock
        except Exception as e:
            self.logger.error(f"Failed to create SCTP socket: {e}")
            return None
    
    def create_m3ua_response(self, req_class, req_type, parameters=None):
        """Create M3UA response message"""
        if parameters is None:
            parameters = []
        
        # Map request to response
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
        
        # Pack parameters
        param_data = b''
        for param in parameters:
            param_data += param.pack()
        
        msg_length = 8 + len(param_data)
        return M3UAMessage(version=1, msg_class=req_class, 
                          msg_type=resp_type, length=msg_length, 
                          data=param_data)
    
    def encode_gt_digits(self, gt_string):
        """Encode GT digits in BCD format"""
        digits = gt_string
        if len(digits) % 2:
            digits += 'F'
        
        encoded = b''
        for i in range(0, len(digits), 2):
            d1 = int(digits[i+1] if i+1 < len(gt_string) else 15)
            d2 = int(digits[i])
            encoded += struct.pack('!B', (d1 << 4) | d2)
        
        return encoded
    
    def create_sri_sm_response(self, invoke_id, msisdn):
        """Create MAP SRI-SM Response with proper ASN.1 encoding"""
        self.logger.info(f"Creating SRI-SM Response for MSISDN: {msisdn}, Invoke ID: {invoke_id}")
        
        # Encode Network Node Number (NNN) as AddressString
        nnn_digits = CONFIG['local_gt']
        # TON/NPI byte: International number (001) + ISDN numbering (0001) = 0x91
        ton_npi = 0x91
        nnn_bcd = self.encode_bcd_digits(nnn_digits)
        nnn_address_string = bytes([ton_npi]) + nnn_bcd
        
        # LocationInfoWithLMSI ::= SEQUENCE
        location_info_elements = []
        
        # networkNode-Number [0] ISDN-AddressString
        nnn_element = self.encode_asn1_tag_length(0x80, nnn_address_string)  # Context [0] IMPLICIT
        location_info_elements.append(nnn_element)
        
        # lmsi [1] LMSI OPTIONAL (4 bytes)
        lmsi_value = struct.pack('!I', 0x12345678)
        lmsi_element = self.encode_asn1_tag_length(0x81, lmsi_value)  # Context [1] IMPLICIT
        location_info_elements.append(lmsi_element)
        
        # Assemble LocationInfoWithLMSI SEQUENCE
        location_info_data = b''.join(location_info_elements)
        location_info = self.encode_asn1_tag_length(0x30, location_info_data)  # SEQUENCE
        
        # TCAP ReturnResult Parameter
        # parameter [0] EXPLICIT (contains the LocationInfoWithLMSI)
        parameter = self.encode_asn1_tag_length(0xA0, location_info)
        
        # operationCode INTEGER
        op_code = self.encode_asn1_tag_length(0x02, bytes([MAP_SRI_SM_RESP]))
        
        # invokeId INTEGER
        invoke_id_encoded = self.encode_asn1_tag_length(0x02, bytes([invoke_id]))
        
        # ReturnResult SEQUENCE
        return_result_data = invoke_id_encoded + op_code + parameter
        return_result = self.encode_asn1_tag_length(0x30, return_result_data)
        
        # Component [2] ReturnResult
        component = self.encode_asn1_tag_length(0xA2, return_result)
        
        # TCAP End with components
        tcap_components = component
        
        # otid (Originating Transaction ID) - echo back the client's dtid
        otid = self.encode_asn1_tag_length(0x48, bytes([0x12, 0x34, 0x56, 0x78]))  # Example OTID
        
        # TCAP End SEQUENCE  
        tcap_end_data = otid + tcap_components
        tcap_end = self.encode_asn1_tag_length(TCAP_END, tcap_end_data)
        
        self.logger.info(f"Created TCAP End message: {len(tcap_end)} bytes")
        self.logger.info(f"SRI-SM Response hex: {tcap_end[:50].hex()}")
        
        return tcap_end
    
    def encode_asn1_tag_length(self, tag, data):
        """Encode ASN.1 TLV structure"""
        length = len(data)
        if length < 0x80:
            # Short form
            return bytes([tag, length]) + data
        else:
            # Long form
            length_bytes = []
            temp_length = length
            while temp_length > 0:
                length_bytes.insert(0, temp_length & 0xFF)
                temp_length >>= 8
            return bytes([tag, 0x80 | len(length_bytes)]) + bytes(length_bytes) + data
    
    def encode_bcd_digits(self, digits_str):
        """Encode decimal digits in BCD format (proper BCD encoding)"""
        digits = digits_str
        if len(digits) % 2:
            digits += 'F'  # Pad with F for odd length
        
        encoded = b''
        for i in range(0, len(digits), 2):
            # BCD encoding: first digit in lower nibble, second digit in upper nibble
            d1 = int(digits[i]) if digits[i] != 'F' else 15
            d2 = int(digits[i+1]) if i+1 < len(digits_str) and digits[i+1] != 'F' else 15
            encoded += struct.pack('!B', (d2 << 4) | d1)
        
        return encoded
    
    def parse_sri_sm_request(self, sccp_data):
        """Parse SRI-SM request from SCCP data with detailed logging"""
        try:
            self.logger.info(f"Parsing SCCP data: {len(sccp_data)} bytes")
            self.logger.info(f"SCCP hex dump: {sccp_data[:50].hex()}")
            self.logger.debug(f"Full SCCP data: {sccp_data.hex()}")

            invoke_id = 1
            msisdn = None

            for i in range(len(sccp_data) - 10):
                if sccp_data[i] == 0x02 and sccp_data[i+1] == 0x01:
                    invoke_id = sccp_data[i+2]
                    self.logger.info(f"Found TCAP invoke ID: {invoke_id} at offset {i}")
                    self.logger.debug(f"Invoke ID bytes: {sccp_data[i:i+3].hex()}")

                if sccp_data[i] == 0x02 and sccp_data[i+1] == 0x01 and sccp_data[i+2] == 0x2D:
                    self.logger.info("Found MAP SRI-SM operation code (45) at offset {i}")
                    self.logger.debug(f"Operation code bytes: {sccp_data[i:i+3].hex()}")

                if sccp_data[i] == 0x80:
                    length = sccp_data[i + 1]
                    self.logger.debug(f"Context [0] IMPLICIT tag at offset {i}, length {length}")
                    if 3 <= length <= 15:
                        msisdn_bcd = sccp_data[i + 2:i + 2 + length]
                        self.logger.debug(f"MSISDN BCD bytes: {msisdn_bcd.hex()}")
                        msisdn = self.decode_bcd_msisdn(msisdn_bcd)
                        self.logger.info(f"Found MSISDN (pattern 1): {msisdn}")
                        break

                if sccp_data[i] == 0x81:
                    length = sccp_data[i + 1]
                    self.logger.debug(f"Context [1] IMPLICIT tag at offset {i}, length {length}")
                    if 3 <= length <= 15:
                        msisdn_bcd = sccp_data[i + 2:i + 2 + length]
                        self.logger.debug(f"MSISDN BCD bytes: {msisdn_bcd.hex()}")
                        msisdn = self.decode_bcd_msisdn(msisdn_bcd)
                        self.logger.info(f"Found MSISDN (pattern 2): {msisdn}")
                        break

                if sccp_data[i] == 0x04:
                    length = sccp_data[i + 1]
                    self.logger.debug(f"OCTET STRING tag at offset {i}, length {length}")
                    if 4 <= length <= 16:
                        if i + 3 < len(sccp_data):
                            msisdn_bcd = sccp_data[i + 3:i + 2 + length]
                            self.logger.debug(f"MSISDN BCD bytes: {msisdn_bcd.hex()}")
                            msisdn = self.decode_bcd_msisdn(msisdn_bcd)
                            self.logger.info(f"Found MSISDN (pattern 3): {msisdn}")
                            break

            if not msisdn:
                msisdn = CONFIG['remote_gt']
                self.logger.warning(f"MSISDN not found in request, using remote GT: {msisdn}")

            return msisdn, invoke_id

        except Exception as e:
            self.logger.error(f"Error parsing SRI-SM request: {e}")
            return CONFIG['remote_gt'], 1

    def decode_bcd_msisdn(self, bcd_data):
        """Decode BCD encoded MSISDN"""
        try:
            self.logger.debug(f"Decoding BCD MSISDN: {bcd_data.hex()}")
            msisdn = ""
            for byte in bcd_data:
                d1 = byte & 0x0F
                d2 = (byte >> 4) & 0x0F
                self.logger.debug(f"BCD byte: {byte:02x}, d1: {d1}, d2: {d2}")
                if d2 != 15:
                    msisdn = str(d2) + msisdn
                if d1 != 15:
                    msisdn = str(d1) + msisdn
            self.logger.debug(f"Decoded MSISDN (reversed): {msisdn[::-1]}")
            return msisdn[::-1] if msisdn else None
        except Exception as e:
            self.logger.error(f"Error decoding BCD MSISDN: {e}")
            return None
    
    def create_sccp_response(self, calling_addr, called_addr, tcap_data):
        """Create SCCP UDT response"""
        # SCCP UDT Header
        sccp_type = SCCP_UDT
        protocol_class = 0x00  # Class 0
        
        # Create addresses
        called_sccp = SCCPAddress(gt=calling_addr['gt'], pc=calling_addr['pc'], ssn=calling_addr['ssn'])
        calling_sccp = SCCPAddress(gt=called_addr['gt'], pc=called_addr['pc'], ssn=called_addr['ssn'])
        
        called_addr_data = called_sccp.pack()
        calling_addr_data = calling_sccp.pack()
        
        # Calculate pointer values
        ptr1 = 3  # Points after the 3 pointer bytes
        ptr2 = ptr1 + len(called_addr_data)
        ptr3 = ptr2 + len(calling_addr_data)
        
        # Build SCCP UDT
        sccp_header = struct.pack('!BBBB', sccp_type, protocol_class, ptr1, ptr2)
        sccp_header += struct.pack('!B', ptr3)
        sccp_data = sccp_header + called_addr_data + calling_addr_data + tcap_data
        
        return sccp_data
    
    def create_m3ua_data_message(self, dest_pc, orig_pc, sccp_data):
        """Create M3UA DATA message"""
        # ITU-T MTP3 Header (5 bytes):
        # Byte 0: (NI << 2) | SI
        # Byte 1-2: DPC (Destination Point Code, 2 bytes, LSB first)
        # Byte 3-4: OPC (Originating Point Code, 2 bytes, LSB first)
        ni = CONFIG['network_indicator']  # Usually 2 for international
        si = 3  # SCCP
        # Correct header: first byte, then DPC (LSB first), then OPC (LSB first)
        mtp3_header = struct.pack('!B', (ni << 2) | si) + struct.pack('<H', dest_pc) + struct.pack('<H', orig_pc)
        protocol_data = mtp3_header + sccp_data

        # M3UA Parameters
        params = []
        rc_param = M3UAParameter(M3UA_PARAM_ROUTING_CONTEXT, struct.pack('!I', CONFIG['route_context']))
        params.append(rc_param)
        pd_param = M3UAParameter(M3UA_PARAM_PROTOCOL_DATA, protocol_data)
        params.append(pd_param)

        param_data = b''.join([p.pack() for p in params])
        msg_length = 8 + len(param_data)
        return M3UAMessage(version=1, msg_class=M3UA_TRANSFER_CLASS,
                          msg_type=M3UA_DATA, length=msg_length,
                          data=param_data)
    
    def handle_m3ua_data(self, m3ua_msg, conn, addr):
        """Handle M3UA DATA message containing SCCP/MAP with robust MTP3 header search and enhanced logging"""
        try:
            self.logger.info(f"Processing M3UA DATA message: {len(m3ua_msg.data)} bytes")
            self.logger.info(f"M3UA raw data: {m3ua_msg.data.hex()}")

            # Parse parameters
            offset = 0
            protocol_data = None
            routing_context = None

            while offset < len(m3ua_msg.data):
                param, param_len = M3UAParameter.unpack(m3ua_msg.data[offset:])
                if not param or param_len == 0:
                    self.logger.warning(f"Failed to unpack parameter at offset {offset}")
                    break

                self.logger.debug(f"Unpacked M3UA param tag: 0x{param.tag:04X}, length: {param.length}, padded_len: {param_len}, offset: {offset}")
                if param.tag == M3UA_PARAM_PROTOCOL_DATA:
                    protocol_data = param.value
                    self.logger.info(f"Found Protocol Data: {len(protocol_data)} bytes")
                    self.logger.info(f"Protocol Data (hex): {protocol_data.hex()}")
                elif param.tag == M3UA_PARAM_ROUTING_CONTEXT:
                    routing_context = struct.unpack('!I', param.value)[0]
                    self.logger.info(f"Found Routing Context: {routing_context}")

                offset += param_len

            if not protocol_data:
                self.logger.error("No Protocol Data found in M3UA message. Check M3UA parameter parsing!")
                return

            # Now protocol_data should start with MTP3 header
            self.logger.info(f"Protocol Data hex (first 32 bytes): {protocol_data[:32].hex()}")
            # Print raw Protocol Data bytes
            self.logger.info(f"Protocol Data (hex): {protocol_data.hex()}")

                # SIGTRAN MTP3 header format (if applicable)
            if protocol_data and len(protocol_data) >= 6:
                # Find the correct offset for MTP3 header
                mtp3_offset = 0  # Adjust this if needed based on your TLV structure
                sio = protocol_data[mtp3_offset]
                opc = struct.unpack('!H', protocol_data[mtp3_offset+2:mtp3_offset+4])[0]
                dpc = struct.unpack('!H', protocol_data[mtp3_offset+6:mtp3_offset+8])[0]
                SI = protocol_data[mtp3_offset+8]
                NI = protocol_data[mtp3_offset+9]
                MP = protocol_data[mtp3_offset+10]
                SLS = protocol_data[mtp3_offset+11]

                self.logger.info("MTP3 Routing Label (SIGTRAN format):")
                self.logger.info(f"  SIO: 0x{sio:02X}")
                self.logger.info(f"  OPC: {opc} (0x{opc:04X})")
                self.logger.info(f"  DPC: {dpc} (0x{dpc:04X})")
                self.logger.info(f"  SI: {SI}")    
                self.logger.info(f"  NI: {NI}")
                self.logger.info(f"  MP: {MP}")
                self.logger.info(f"  SLS: {SLS}")
                self.logger.info(f"  After MTP3 Header (hex): {protocol_data[mtp3_offset:mtp3_offset+9].hex()}")

                # SCCP Message Type (next byte)
                if len(protocol_data) > 6:
                    sccp_type = protocol_data[6]
                    self.logger.info(f"  SCCP Message Type: 0x{sccp_type:02X} ({'UDT' if sccp_type == 0x09 else 'Other'})")

                    # SCCP pointers and fields
                    if len(protocol_data) > 9:
                        ptr_called = protocol_data[7]
                        ptr_calling = protocol_data[8]
                        ptr_data = protocol_data[9]
                        self.logger.info(f"  SCCP Pointers: Called={ptr_called}, Calling={ptr_calling}, Data={ptr_data}")

                        # Protocol Class, Hop Counter
                        if len(protocol_data) > 11:
                            protocol_class = protocol_data[9]
                            hop_counter = protocol_data[10]
                            self.logger.info(f"  SCCP Protocol Class: {protocol_class}")
                            self.logger.info(f"  SCCP Hop Counter: {hop_counter}")

                        # Called Party Address
                        called_addr_offset = 11
                        if len(protocol_data) > called_addr_offset:
                            called_addr_len = protocol_data[called_addr_offset]
                            self.logger.info(f"  Called Party Address Length: {called_addr_len}")
                            if len(protocol_data) > called_addr_offset + 1:
                                called_ai = protocol_data[called_addr_offset + 1]
                                self.logger.info(f"  Called Party Address Indicator: 0x{called_ai:02X}")

                        # You can add more parsing for Calling Party, User Data, etc. here

        except Exception as e:
            self.logger.error(f"Error in handle_m3ua_data: {e}")
        # Optionally add a finally block if you need cleanup
    
    def handle_m3ua_message(self, message, conn, addr):
        """Handle M3UA protocol messages"""
        conn_key = f"{addr[0]}:{addr[1]}"
        
        if conn_key not in self.asp_states:
            self.asp_states[conn_key] = {'state': 'ASP-DOWN'}
        
        asp_state = self.asp_states[conn_key]
        
        if message.msg_class == M3UA_ASPSM_CLASS:
            if message.msg_type == M3UA_ASPUP:
                self.logger.info(f"M3UA ASPUP received from {addr[0]}:{addr[1]}")
                response = self.create_m3ua_response(M3UA_ASPSM_CLASS, M3UA_ASPUP)
                if response:
                    conn.send(response.pack())
                    asp_state['state'] = 'ASP-INACTIVE'
                    self.logger.info(f"M3UA ASPUP-ACK sent to {addr[0]}:{addr[1]}")
            
            elif message.msg_type == M3UA_BEAT:
                self.logger.info(f"M3UA HEARTBEAT received from {addr[0]}:{addr[1]}")
                response = self.create_m3ua_response(M3UA_ASPSM_CLASS, M3UA_BEAT)
                if response:
                    conn.send(response.pack())
                    self.logger.info(f"M3UA HEARTBEAT-ACK sent to {addr[0]}:{addr[1]}")
        
        elif message.msg_class == M3UA_ASPTM_CLASS:
            if message.msg_type == M3UA_ASPAC:
                self.logger.info(f"M3UA ASPAC received from {addr[0]}:{addr[1]}")
                response = self.create_m3ua_response(M3UA_ASPTM_CLASS, M3UA_ASPAC)
                if response:
                    conn.send(response.pack())
                    asp_state['state'] = 'ASP-ACTIVE'
                    self.logger.info(f"M3UA ASPAC-ACK sent to {addr[0]}:{addr[1]}")
        
        elif message.msg_class == M3UA_TRANSFER_CLASS:
            if message.msg_type == M3UA_DATA:
                self.handle_m3ua_data(message, conn, addr)
    
    def handle_client(self, conn, addr):
        """Handle client connection"""
        try:
            self.logger.info(f"SCTP association established with {addr[0]}:{addr[1]}")
            
            while self.running:
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    
                    self.logger.info(f"SCTP DATA received from {addr[0]}:{addr[1]} - {len(data)} bytes")
                    
                    # Parse M3UA message
                    m3ua_msg = M3UAMessage.unpack(data)
                    if m3ua_msg and m3ua_msg.version == 1:
                        self.logger.info(f"M3UA Message - Class: {m3ua_msg.msg_class}, Type: {m3ua_msg.msg_type}")
                        self.handle_m3ua_message(m3ua_msg, conn, addr)
                    
                except socket.timeout:
                    continue
                except socket.error as e:
                    self.logger.warning(f"Client {addr[0]}:{addr[1]} error: {e}")
                    break
        
        except Exception as e:
            self.logger.error(f"Error handling client {addr[0]}:{addr[1]}: {e}")
        finally:
            conn_key = f"{addr[0]}:{addr[1]}"
            if conn_key in self.asp_states:
                del self.asp_states[conn_key]
            conn.close()
            self.logger.info(f"Connection closed with {addr[0]}:{addr[1]}")
    
    def start(self):
        """Start the MAP SIGTRAN server"""
        try:
            if not self.check_sctp_support():
                return
            
            self.socket = self.create_socket()
            if not self.socket:
                return
            
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            
            self.logger.info(f"MAP SIGTRAN Server (SCTP) listening on {self.host}:{self.port}")
            self.logger.info("Ready to handle MAP SRI-SM requests")
            
            self.running = True
            
            while self.running:
                try:
                    conn, addr = self.socket.accept()
                    
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                
                except socket.error as e:
                    if self.running:
                        self.logger.error(f"Accept error: {e}")
                    break
        
        except Exception as e:
            self.logger.error(f"Failed to start server: {e}")
        finally:
            self.cleanup()
    
    def stop(self):
        """Stop the server"""
        self.logger.info("Stopping MAP SIGTRAN server...")
        self.running = False
        if self.socket:
            self.socket.close()
    
    def cleanup(self):
        """Clean up resources"""
        if self.socket:
            self.socket.close()
        self.logger.info("MAP SIGTRAN server stopped")

def main():
    """Main function"""
    print("MAP SIGTRAN Server with SRI-SM Support")
    print("Handles Send Routing Info for Short Message requests")
    print()
    
    server = MAPSIGTRANServer()
    
    try:
        print("Starting MAP SIGTRAN Server on port 2915...")
        print("Configuration:")
        print(f"  Local GT: {CONFIG['local_gt']}, PC: {CONFIG['local_pc']}")
        print(f"  Remote GT: {CONFIG['remote_gt']}, PC: {CONFIG['remote_pc']}")
        print(f"  Route Context: {CONFIG['route_context']}")
        print("Press Ctrl+C to stop")
        print()
        server.start()
    except KeyboardInterrupt:
        print("\nShutdown requested...")
        server.stop()
    except Exception as e:
        print(f"Error: {e}")
        server.stop()

if __name__ == "__main__":
    main()
