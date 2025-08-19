#!/usr/bin/env python3
"""
Enhanced SIGTRAN Server with MAP SRI-SM Support
Handles MAP Send Routing Info for Short Message requests
Supports M3UA/SCCP/TCAP/MAP protocol stack with IMSI and NNN response
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
SCCP_XUDT = 0x11       # Extended Unitdata

# Configuration
CONFIG = {
    'local_gt': '61418079999',
    'local_pc': 6199,
    'remote_gt': '61418706002', 
    'remote_pc': 12092,
    'route_context': 12092,
    'ssn': 6,  # HLR SSN
    'network_indicator': 2,  # International network
    'hlr_gt': '61418079999',  # HLR Global Title
    'msc_gt': '61418080001',  # MSC Global Title for NNN
    'vlr_gt': '61418080002',  # VLR Global Title
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
    """Enhanced SIGTRAN Server with MAP SRI-SM Support"""
    
    def __init__(self, host='0.0.0.0', port=2915):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.asp_states = {}
        self.transaction_id = 1
        self.active_transactions = {}
        
        # Setup logging with more detail
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.logger = logging.getLogger('MAPSIGTRANServer')
        
        # Create file handler for detailed logging
        fh = logging.FileHandler('map_sigtran_server.log')
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)
        
        # Check root privileges
        if os.geteuid() != 0:
            self.logger.error("This server requires root privileges for native SCTP!")
            self.logger.error("Please run with: sudo python3 " + sys.argv[0])
            sys.exit(1)
        
        self.logger.info("=" * 60)
        self.logger.info("MAP SIGTRAN Server Configuration:")
        self.logger.info(f"  Local GT: {CONFIG['local_gt']}, PC: {CONFIG['local_pc']}")
        self.logger.info(f"  Remote GT: {CONFIG['remote_gt']}, PC: {CONFIG['remote_pc']}")
        self.logger.info(f"  Route Context: {CONFIG['route_context']}")
        self.logger.info(f"  HLR GT: {CONFIG['hlr_gt']}")
        self.logger.info(f"  MSC GT: {CONFIG['msc_gt']}")
        self.logger.info(f"  VLR GT: {CONFIG['vlr_gt']}")
        self.logger.info("=" * 60)
    
    def check_sctp_support(self):
        """Check if kernel supports SCTP"""
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_SCTP)
            test_sock.close()
            self.logger.info("SCTP support verified")
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
            #sock.settimeout(1.0)  # Set timeout for non-blocking operations
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
    
    def generate_imsi(self, msisdn):
        """Generate IMSI based on MSISDN"""
        # Extract country and network codes from MSISDN
        # For demonstration, generate a realistic IMSI
        mcc = "614"  # Australia
        mnc = "18"   # Sample network
        msin = msisdn[-10:].zfill(10)  # Take last 10 digits, pad with zeros if needed
        imsi = mcc + mnc + msin
        self.logger.info(f"Generated IMSI: {imsi} from MSISDN: {msisdn}")
        return imsi
    
    def encode_bcd_digits(self, digits_str):
        """Encode decimal digits in BCD format (nibble swapped)"""
        digits = digits_str
        if len(digits) % 2:
            digits += 'F'  # Pad with F for odd length
        
        encoded = b''
        for i in range(0, len(digits), 2):
            # BCD encoding: first digit in lower nibble, second digit in upper nibble
            d1 = int(digits[i]) if digits[i] != 'F' else 15
            d2 = int(digits[i+1]) if i+1 < len(digits_str) and digits[i+1] != 'F' else 15
            encoded += struct.pack('!B', (d2 << 4) | d1)
        
        self.logger.debug(f"Encoded BCD '{digits_str}' -> {encoded.hex()}")
        return encoded
    
    def encode_asn1_tag_length(self, tag, data):
        """Encode ASN.1 TLV structure"""
        length = len(data)
        if length < 0x80:
            # Short form
            result = bytes([tag, length]) + data
        else:
            # Long form
            length_bytes = []
            temp_length = length
            while temp_length > 0:
                length_bytes.insert(0, temp_length & 0xFF)
                temp_length >>= 8
            result = bytes([tag, 0x80 | len(length_bytes)]) + bytes(length_bytes) + data
        
        self.logger.debug(f"ASN.1 TLV: tag=0x{tag:02X}, length={length}, data={data.hex()[:40]}...")
        return result
    
    def create_sri_sm_response(self, invoke_id, msisdn, orig_transaction_id):
        """Create enhanced MAP SRI-SM Response with NNN and IMSI"""
        self.logger.info("=" * 50)
        self.logger.info(f"Creating SRI-SM Response:")
        self.logger.info(f"  MSISDN: {msisdn}")
        self.logger.info(f"  Invoke ID: {invoke_id}")
        self.logger.info(f"  Original Transaction ID: {orig_transaction_id.hex() if orig_transaction_id else 'None'}")
        
        # Generate IMSI for this MSISDN
        imsi = self.generate_imsi(msisdn)
        
        # Encode Network Node Number (MSC GT)
        nnn_gt = CONFIG['msc_gt']
        self.logger.info(f"  NNN (MSC GT): {nnn_gt}")
        
        # TON/NPI byte: International number (001) + ISDN numbering (0001) = 0x91
        ton_npi = 0x91
        nnn_bcd = self.encode_bcd_digits(nnn_gt)
        nnn_address_string = bytes([ton_npi]) + nnn_bcd
        self.logger.debug(f"  NNN AddressString: {nnn_address_string.hex()}")
        
        # Encode IMSI
        imsi_bcd = self.encode_bcd_digits(imsi)
        self.logger.debug(f"  IMSI BCD: {imsi_bcd.hex()}")
        
        # Create LMSI (4 bytes)
        lmsi_value = struct.pack('!I', random.randint(0x10000000, 0xFFFFFFFF))
        self.logger.debug(f"  LMSI: {lmsi_value.hex()}")
        
        # LocationInfoWithLMSI ::= SEQUENCE {
        #   networkNode-Number  [0] ISDN-AddressString,
        #   lmsi                [1] LMSI OPTIONAL,
        #   ... }
        location_info_elements = []
        
        # networkNode-Number [0] ISDN-AddressString (IMPLICIT)
        nnn_element = self.encode_asn1_tag_length(ASN1_CONTEXT_0, nnn_address_string)
        location_info_elements.append(nnn_element)
        self.logger.debug(f"  NNN Element: {nnn_element.hex()}")
        
        # lmsi [1] LMSI OPTIONAL (IMPLICIT)
        lmsi_element = self.encode_asn1_tag_length(ASN1_CONTEXT_1, lmsi_value)
        location_info_elements.append(lmsi_element)
        self.logger.debug(f"  LMSI Element: {lmsi_element.hex()}")
        
        # Assemble LocationInfoWithLMSI SEQUENCE
        location_info_data = b''.join(location_info_elements)
        location_info = self.encode_asn1_tag_length(ASN1_SEQUENCE, location_info_data)
        self.logger.debug(f"  LocationInfo: {location_info.hex()}")
        
        # Add IMSI as additional info [2] IMSI OPTIONAL
        imsi_element = self.encode_asn1_tag_length(ASN1_CONTEXT_2, imsi_bcd)
        location_info_with_imsi = location_info_data + imsi_element
        location_info_complete = self.encode_asn1_tag_length(ASN1_SEQUENCE, location_info_with_imsi)
        self.logger.debug(f"  LocationInfo with IMSI: {location_info_complete.hex()}")
        
        # TCAP ReturnResult Parameter (EXPLICIT)
        parameter = self.encode_asn1_tag_length(0xA0, location_info_complete)
        
        # operationCode INTEGER
        op_code = self.encode_asn1_tag_length(ASN1_INTEGER, bytes([MAP_SRI_SM_RESP]))
        
        # invokeId INTEGER
        invoke_id_encoded = self.encode_asn1_tag_length(ASN1_INTEGER, bytes([invoke_id & 0xFF]))
        
        # ReturnResult SEQUENCE
        return_result_data = invoke_id_encoded + op_code + parameter
        return_result = self.encode_asn1_tag_length(ASN1_SEQUENCE, return_result_data)
        
        # Component [2] ReturnResult
        component = self.encode_asn1_tag_length(0xA2, return_result)
        
        # otid (Originating Transaction ID) - echo back or generate new
        if orig_transaction_id and len(orig_transaction_id) >= 4:
            otid_value = orig_transaction_id
        else:
            otid_value = struct.pack('!I', random.randint(0x10000000, 0xFFFFFFFF))
        
        otid = self.encode_asn1_tag_length(0x48, otid_value)
        
        # TCAP End SEQUENCE  
        tcap_end_data = otid + component
        tcap_end = self.encode_asn1_tag_length(TCAP_END, tcap_end_data)
        
        self.logger.info(f"  TCAP End message created: {len(tcap_end)} bytes")
        self.logger.debug(f"  Complete TCAP End: {tcap_end.hex()}")
        self.logger.info("=" * 50)
        
        return tcap_end
    
    def decode_bcd_digits(self, bcd_data):
        """Decode BCD encoded digits with detailed logging"""
        try:
            self.logger.debug(f"Decoding BCD data: {bcd_data.hex()}")
            digits = ""
            for i, byte in enumerate(bcd_data):
                d1 = byte & 0x0F
                d2 = (byte >> 4) & 0x0F
                self.logger.debug(f"  Byte {i}: 0x{byte:02X} -> d1={d1}, d2={d2}")
                if d1 != 15:  # 15 = 0xF (filler)
                    digits += str(d1)
                if d2 != 15:
                    digits += str(d2)
            self.logger.debug(f"Decoded digits: '{digits}'")
            return digits if digits else None
        except Exception as e:
            self.logger.error(f"Error decoding BCD digits: {e}")
            return None
    
    def parse_sccp_addresses(self, sccp_data, offset):
        """Parse SCCP addresses with enhanced logging"""
        addresses = {'called': {}, 'calling': {}}
        
        try:
            if offset + 3 >= len(sccp_data):
                self.logger.error("SCCP data too short for address parsing")
                return addresses, offset
            
            # Get pointers
            ptr_called = sccp_data[offset]
            ptr_calling = sccp_data[offset + 1] 
            ptr_data = sccp_data[offset + 2]
            
            self.logger.debug(f"SCCP Address Pointers: Called={ptr_called}, Calling={ptr_calling}, Data={ptr_data}")
            
            # Parse Called Party Address
            called_addr_start = offset + ptr_called
            if called_addr_start < len(sccp_data):
                called_addr_len = sccp_data[called_addr_start]
                self.logger.debug(f"Called Address Length: {called_addr_len}")
                
                if called_addr_start + called_addr_len < len(sccp_data):
                    called_addr_data = sccp_data[called_addr_start + 1:called_addr_start + 1 + called_addr_len]
                    addresses['called'] = self.parse_single_sccp_address(called_addr_data, "Called")
            
            # Parse Calling Party Address
            calling_addr_start = offset + ptr_calling
            if calling_addr_start < len(sccp_data):
                calling_addr_len = sccp_data[calling_addr_start]
                self.logger.debug(f"Calling Address Length: {calling_addr_len}")
                
                if calling_addr_start + calling_addr_len < len(sccp_data):
                    calling_addr_data = sccp_data[calling_addr_start + 1:calling_addr_start + 1 + calling_addr_len]
                    addresses['calling'] = self.parse_single_sccp_address(calling_addr_data, "Calling")
            
            # Return data start position
            data_start = offset + ptr_data
            return addresses, data_start
            
        except Exception as e:
            self.logger.error(f"Error parsing SCCP addresses: {e}")
            return addresses, offset
    
    def parse_single_sccp_address(self, addr_data, addr_type):
        """Parse a single SCCP address"""
        address = {'gt': None, 'pc': None, 'ssn': None}
        
        try:
            if len(addr_data) < 1:
                return address
                
            ai = addr_data[0]  # Address Indicator
            self.logger.debug(f"{addr_type} Address Indicator: 0x{ai:02X}")
            
            offset = 1
            
            # Point Code
            if ai & SCCP_AI_PC_PRESENT:
                if offset + 2 <= len(addr_data):
                    pc = struct.unpack('!H', addr_data[offset:offset+2])[0]
                    address['pc'] = pc
                    offset += 2
                    self.logger.debug(f"{addr_type} Point Code: {pc}")
            
            # SSN
            if ai & SCCP_AI_SSN_PRESENT:
                if offset < len(addr_data):
                    ssn = addr_data[offset]
                    address['ssn'] = ssn
                    offset += 1
                    self.logger.debug(f"{addr_type} SSN: {ssn}")
            
            # Global Title
            if ai & SCCP_AI_GT_PRESENT:
                if offset < len(addr_data):
                    gt_data = addr_data[offset:]
                    self.logger.debug(f"{addr_type} GT Data: {gt_data.hex()}")
                    
                    # Skip GT indicator bytes (TT, NP, NOA)
                    if len(gt_data) >= 3:
                        gt_bcd = gt_data[3:]  # Skip first 3 bytes (TT, NP+Enc, NOA)
                        gt = self.decode_bcd_digits(gt_bcd)
                        address['gt'] = gt
                        self.logger.debug(f"{addr_type} GT: {gt}")
                        
        except Exception as e:
            self.logger.error(f"Error parsing {addr_type} address: {e}")
            
        return address
    
    def parse_tcap_message(self, tcap_data):
        """Parse TCAP message with comprehensive logging"""
        try:
            self.logger.info(f"Parsing TCAP message: {len(tcap_data)} bytes")
            self.logger.debug(f"TCAP raw data: {tcap_data.hex()}")
            
            if len(tcap_data) < 2:
                self.logger.error("TCAP data too short")
                return None, None, None, None
            
            tcap_tag = tcap_data[0]
            tcap_len = tcap_data[1]
            
            self.logger.info(f"TCAP Tag: 0x{tcap_tag:02X} ({'BEGIN' if tcap_tag == TCAP_BEGIN else 'OTHER'})")
            self.logger.info(f"TCAP Length: {tcap_len}")
            
            if tcap_tag != TCAP_BEGIN:
                self.logger.warning(f"Expected TCAP BEGIN (0x62), got 0x{tcap_tag:02X}")
            
            # Parse TCAP components
            transaction_id = None
            invoke_id = None
            msisdn = None
            
            # Look for transaction ID (dtid)
            for i in range(len(tcap_data) - 4):
                # Look for dtid tag (0x49)
                if tcap_data[i] == 0x49:
                    tid_len = tcap_data[i + 1]
                    if tid_len <= 4 and i + 2 + tid_len <= len(tcap_data):
                        transaction_id = tcap_data[i + 2:i + 2 + tid_len]
                        self.logger.info(f"Found Transaction ID: {transaction_id.hex()}")
                        break
            
            # Look for invoke ID and operation code
            for i in range(len(tcap_data) - 10):
                # Look for invoke ID (INTEGER tag 0x02)
                if tcap_data[i] == ASN1_INTEGER and tcap_data[i + 1] == 0x01:
                    invoke_id = tcap_data[i + 2]
                    self.logger.info(f"Found Invoke ID: {invoke_id}")
                
                # Look for MAP SRI-SM operation code
                if (tcap_data[i] == ASN1_INTEGER and tcap_data[i + 1] == 0x01 and 
                    tcap_data[i + 2] == MAP_SRI_SM):
                    self.logger.info(f"Found MAP SRI-SM operation code at offset {i}")
            
            # Enhanced MSISDN parsing with multiple patterns
            msisdn = self.extract_msisdn_from_tcap(tcap_data)
            
            return transaction_id, invoke_id, msisdn, tcap_data
            
        except Exception as e:
            self.logger.error(f"Error parsing TCAP message: {e}")
            return None, None, None, None
    
    def extract_msisdn_from_tcap(self, tcap_data):
        """Extract MSISDN from TCAP data with multiple search patterns"""
        msisdn = None
        
        self.logger.debug("Searching for MSISDN in TCAP data...")
        
        # Pattern 1: Look for AddressString after invoke parameters
        for i in range(len(tcap_data) - 5):
            # Look for OCTET STRING or context tags containing phone numbers
            if tcap_data[i] in [0x04, 0x80, 0x81, 0x82]:  # OCTET_STRING or context tags
                length = tcap_data[i + 1]
                if 3 <= length <= 15:  # Reasonable length for phone number
                    if i + 2 + length <= len(tcap_data):
                        # Check if this looks like a phone number (starts with TON/NPI)
                        potential_data = tcap_data[i + 2:i + 2 + length]
                        if len(potential_data) > 0:
                            # Check for international TON/NPI (0x91)
                            if potential_data[0] == 0x91:
                                msisdn_bcd = potential_data[1:]
                                msisdn = self.decode_bcd_digits(msisdn_bcd)
                                if msisdn and len(msisdn) >= 8:  # Valid phone number length
                                    self.logger.info(f"Found MSISDN (Pattern TON/NPI): {msisdn}")
                                    return msisdn
                            else:
                                # Try direct BCD decoding
                                msisdn = self.decode_bcd_digits(potential_data)
                                if msisdn and len(msisdn) >= 8:
                                    self.logger.info(f"Found MSISDN (Pattern BCD): {msisdn}")
                                    return msisdn
        
        # Pattern 2: Search for specific MAP parameter patterns
        for i in range(len(tcap_data) - 10):
            # Look for sequence of bytes that might indicate MSISDN parameter
            if tcap_data[i:i+3] == bytes([0x30, 0x0A, 0x80]):  # Common MAP parameter pattern
                if i + 5 < len(tcap_data):
                    length = tcap_data[i + 4]
                    if 3 <= length <= 12:
                        msisdn_data = tcap_data[i + 5:i + 5 + length]
                        msisdn = self.decode_bcd_digits(msisdn_data)
                        if msisdn and len(msisdn) >= 8:
                            self.logger.info(f"Found MSISDN (Pattern MAP): {msisdn}")
                            return msisdn
        
        # Fallback: Use configured remote GT
        if not msisdn:
            msisdn = CONFIG['remote_gt']
            self.logger.warning(f"MSISDN not found in TCAP data, using configured remote GT: {msisdn}")
        
        return msisdn
    
    def create_sccp_response(self, calling_addr, called_addr, tcap_data):
        """Create SCCP UDT response with detailed logging"""
        try:
            self.logger.info("Creating SCCP UDT Response:")
            self.logger.info(f"  Original Calling: GT={calling_addr.get('gt')}, PC={calling_addr.get('pc')}, SSN={calling_addr.get('ssn')}")
            self.logger.info(f"  Original Called: GT={called_addr.get('gt')}, PC={called_addr.get('pc')}, SSN={called_addr.get('ssn')}")
            
            # SCCP UDT Header
            sccp_type = SCCP_UDT
            protocol_class = 0x00  # Class 0
            
            # Swap addresses for response (called becomes calling, calling becomes called)
            response_called = SCCPAddress(
                gt=calling_addr.get('gt'), 
                pc=calling_addr.get('pc'), 
                ssn=calling_addr.get('ssn')
            )
            response_calling = SCCPAddress(
                gt=called_addr.get('gt') or CONFIG['hlr_gt'], 
                pc=called_addr.get('pc') or CONFIG['local_pc'], 
                ssn=called_addr.get('ssn') or CONFIG['ssn']
            )
            
            self.logger.info(f"  Response Called: GT={response_called.gt}, PC={response_called.pc}, SSN={response_called.ssn}")
            self.logger.info(f"  Response Calling: GT={response_calling.gt}, PC={response_calling.pc}, SSN={response_calling.ssn}")
            
            called_addr_data = response_called.pack()
            calling_addr_data = response_calling.pack()
            
            self.logger.debug(f"  Called Address Data: {called_addr_data.hex()}")
            self.logger.debug(f"  Calling Address Data: {calling_addr_data.hex()}")
            
            # Calculate pointer values (relative to start of pointers)
            ptr1 = 3  # Points to called address after 3 pointer bytes
            ptr2 = ptr1 + len(called_addr_data)
            ptr3 = ptr2 + len(calling_addr_data)
            
            self.logger.debug(f"  SCCP Pointers: ptr1={ptr1}, ptr2={ptr2}, ptr3={ptr3}")
            
            # Build SCCP UDT
            sccp_header = struct.pack('!BBBB', sccp_type, protocol_class, ptr1, ptr2)
            sccp_header += struct.pack('!B', ptr3)
            sccp_data = sccp_header + called_addr_data + calling_addr_data + tcap_data
            
            self.logger.info(f"  Complete SCCP UDT Response: {len(sccp_data)} bytes")
            self.logger.debug(f"  SCCP Response: {sccp_data.hex()}")
            
            return sccp_data
            
        except Exception as e:
            self.logger.error(f"Error creating SCCP response: {e}")
            return None
    
    def create_m3ua_data_message(self, dest_pc, orig_pc, sccp_data):
        """Create M3UA DATA message with enhanced logging"""
        try:
            self.logger.info("Creating M3UA DATA Message:")
            self.logger.info(f"  Destination PC: {dest_pc}")
            self.logger.info(f"  Originating PC: {orig_pc}")
            self.logger.info(f"  SCCP Data Length: {len(sccp_data)} bytes")
            
            # MTP3 Header (5 bytes for ITU-T format):
            ni = CONFIG['network_indicator']  # Network Indicator
            si = 3  # Service Indicator (SCCP)
            sls = 0  # Signaling Link Selection
            
            # Encode MTP3 header: SIO + DPC (2 bytes, LSB first) + OPC (2 bytes, LSB first)
            sio = (ni << 2) | si
            mtp3_header = struct.pack('!B', sio)  # SIO
            mtp3_header += struct.pack('<H', dest_pc)  # DPC (Little Endian)
            mtp3_header += struct.pack('<H', orig_pc)   # OPC (Little Endian)
            
            self.logger.debug(f"  MTP3 Header: {mtp3_header.hex()}")
            self.logger.debug(f"    SIO: 0x{sio:02X} (NI={ni}, SI={si})")
            self.logger.debug(f"    DPC: {dest_pc} (0x{dest_pc:04X})")
            self.logger.debug(f"    OPC: {orig_pc} (0x{orig_pc:04X})")
            
            protocol_data = mtp3_header + sccp_data
            
            # M3UA Parameters
            params = []
            
            # Routing Context
            rc_param = M3UAParameter(M3UA_PARAM_ROUTING_CONTEXT, 
                                   struct.pack('!I', CONFIG['route_context']))
            params.append(rc_param)
            self.logger.debug(f"  Routing Context: {CONFIG['route_context']}")
            
            # Protocol Data
            pd_param = M3UAParameter(M3UA_PARAM_PROTOCOL_DATA, protocol_data)
            params.append(pd_param)
            
            param_data = b''.join([p.pack() for p in params])
            msg_length = 8 + len(param_data)
            
            m3ua_msg = M3UAMessage(version=1, msg_class=M3UA_TRANSFER_CLASS,
                                 msg_type=M3UA_DATA, length=msg_length,
                                 data=param_data)
            
            self.logger.info(f"  M3UA DATA Message: {msg_length} bytes total")
            self.logger.debug(f"  Complete M3UA Message: {m3ua_msg.pack().hex()}")
            
            return m3ua_msg
            
        except Exception as e:
            self.logger.error(f"Error creating M3UA DATA message: {e}")
            return None
    
    def handle_m3ua_data(self, m3ua_msg, conn, addr):
        """Handle M3UA DATA message containing SCCP/MAP with comprehensive parsing"""
        try:
            self.logger.info("=" * 60)
            self.logger.info(f"Processing M3UA DATA from {addr[0]}:{addr[1]}")
            self.logger.info(f"M3UA Message Length: {len(m3ua_msg.data)} bytes")
            self.logger.debug(f"M3UA raw data: {m3ua_msg.data.hex()}")

            # Parse M3UA parameters
            offset = 0
            protocol_data = None
            routing_context = None

            while offset < len(m3ua_msg.data):
                param, param_len = M3UAParameter.unpack(m3ua_msg.data[offset:])
                if not param or param_len == 0:
                    self.logger.warning(f"Failed to unpack parameter at offset {offset}")
                    break

                self.logger.debug(f"M3UA Parameter: tag=0x{param.tag:04X}, length={param.length}")
                
                if param.tag == M3UA_PARAM_PROTOCOL_DATA:
                    protocol_data = param.value
                    self.logger.info(f"Found Protocol Data: {len(protocol_data)} bytes")
                    
                elif param.tag == M3UA_PARAM_ROUTING_CONTEXT:
                    routing_context = struct.unpack('!I', param.value)[0]
                    self.logger.info(f"Found Routing Context: {routing_context}")

                offset += param_len

            if not protocol_data:
                self.logger.error("No Protocol Data found in M3UA message")
                return

            self.logger.debug(f"Protocol Data: {protocol_data.hex()}")


            # Find the actual MTP3 header - look for SIO byte pattern
            mtp3_offset = None
            for i in range(len(protocol_data) - 5):
                # Look for SIO pattern: service indicator 3 (SCCP) with network indicator
                if protocol_data[i] in [0x03, 0x83, 0x0B, 0x8B]:  # Common SCCP SIO values
                      mtp3_offset = i
                      break

            if mtp3_offset is None:
                # Fallback: try fixed offset 8 (common for SIGTRAN)
                mtp3_offset = 8

            if len(protocol_data) >= mtp3_offset + 5:
                sio = protocol_data[mtp3_offset]
                dpc = struct.unpack('<H', protocol_data[mtp3_offset+1:mtp3_offset+3])[0]
                opc = struct.unpack('<H', protocol_data[mtp3_offset+3:mtp3_offset+5])[0]

                # SCCP data starts after 9 bytes (4 SIGTRAN + 5 MTP3)
                sccp_data = protocol_data[9:]

                ni = (sio >> 2) & 0x03
                si = sio & 0x03
                
                self.logger.info(f"MTP3 Header:")
                self.logger.info(f"  SIO: 0x{sio:02X} (NI={ni}, SI={si})")
                self.logger.info(f"  DPC: {dpc} (0x{dpc:04X})")
                self.logger.info(f"  OPC: {opc} (0x{opc:04X})")
                
                # SCCP data starts after MTP3 header
                sccp_data = protocol_data[mtp3_offset + 5:]
                self.logger.info(f"SCCP Data: {len(sccp_data)} bytes")
                self.logger.debug(f"SCCP Data: {sccp_data.hex()}")
                
                if len(sccp_data) > 0:
                    sccp_type = sccp_data[0]
                    self.logger.info(f"SCCP Message Type: 0x{sccp_type:02X} ({'UDT' if sccp_type == 0x09 else 'XUDT' if sccp_type == 0x11 else 'Other'})") 
                    
                    if sccp_type == SCCP_UDT or sccp_type == SCCP_XUDT:
                        self.handle_sccp_udt(sccp_data, opc, dpc, conn, addr)
                    else:
                        self.logger.warning(f"Unsupported SCCP message type: 0x{sccp_type:02X}")
            else:
                self.logger.error("Protocol data too short for MTP3 header")

        except Exception as e:
            self.logger.error(f"Error in handle_m3ua_data: {e}")
        finally:
            self.logger.info("=" * 60)
    
    def handle_sccp_udt(self, sccp_data, orig_pc, dest_pc, conn, addr):
        """Handle SCCP UDT message"""
        try:
            self.logger.info("Processing SCCP UDT Message:")
            
            if len(sccp_data) < 5:
                self.logger.error("SCCP UDT data too short")
                return
            
            protocol_class = sccp_data[1]
            self.logger.info(f"  Protocol Class: {protocol_class}")
            
            # Parse SCCP addresses and get TCAP data
            addresses, tcap_offset = self.parse_sccp_addresses(sccp_data, 2)
            
            if tcap_offset < len(sccp_data):
                tcap_data = sccp_data[tcap_offset:]
                self.logger.info(f"  TCAP Data: {len(tcap_data)} bytes")
                self.logger.debug(f"  TCAP Data: {tcap_data.hex()}")
                
                # Parse TCAP message
                transaction_id, invoke_id, msisdn, _ = self.parse_tcap_message(tcap_data)
                
                if invoke_id is not None and msisdn:
                    # Create SRI-SM response
                    response_tcap = self.create_sri_sm_response(invoke_id, msisdn, transaction_id)
                    
                    # Create SCCP response
                    sccp_response = self.create_sccp_response(
                        addresses['calling'], 
                        addresses['called'], 
                        response_tcap
                    )
                    
                    if sccp_response:
                        # Create M3UA DATA response
                        m3ua_response = self.create_m3ua_data_message(
                            orig_pc,  # Send back to originator
                            dest_pc,  # From destination
                            sccp_response
                        )
                        
                        if m3ua_response:
                            response_data = m3ua_response.pack()
                            conn.send(response_data)
                            self.logger.info(f"Sent SRI-SM Response: {len(response_data)} bytes")
                            self.logger.info(f"  MSISDN: {msisdn}")
                            self.logger.info(f"  NNN: {CONFIG['msc_gt']}")
                            self.logger.info(f"  IMSI: {self.generate_imsi(msisdn)}")
                        else:
                            self.logger.error("Failed to create M3UA response")
                    else:
                        self.logger.error("Failed to create SCCP response")
                else:
                    self.logger.warning("Could not extract invoke_id or MSISDN from TCAP message")
            else:
                self.logger.error("No TCAP data found in SCCP UDT")
                
        except Exception as e:
            self.logger.error(f"Error handling SCCP UDT: {e}")
    
    def handle_m3ua_data(self, m3ua_msg, conn, addr):
      """Handle M3UA DATA message containing SCCP/MAP with comprehensive parsing"""
      try:
        self.logger.info("=" * 60)
        self.logger.info(f"Processing M3UA DATA from {addr[0]}:{addr[1]}")
        self.logger.info(f"M3UA Message Length: {len(m3ua_msg.data)} bytes")
        self.logger.debug(f"M3UA raw data: {m3ua_msg.data.hex()}")

        # Parse M3UA parameters
        offset = 0
        protocol_data = None
        routing_context = None

        while offset < len(m3ua_msg.data):
            param, param_len = M3UAParameter.unpack(m3ua_msg.data[offset:])
            if not param or param_len == 0:
                self.logger.warning(f"Failed to unpack parameter at offset {offset}")
                break

            # Detailed parameter logging
            self.logger.info(f"M3UA Parameter Details:")
            self.logger.info(f"  Tag: {param.tag} (0x{param.tag:04X})")
            self.logger.info(f"  Length: {param.length} (0x{param.length:04X})")
            self.logger.info(f"  Value Length: {len(param.value)} bytes")
            self.logger.info(f"  Padded Length: {param_len} bytes")
            
            if len(param.value) <= 32:  # Show hex for small values
                self.logger.info(f"  Value (hex): {param.value.hex()}")
            else:
                self.logger.info(f"  Value (hex, first 32 bytes): {param.value[:32].hex()}...")
            
            if param.tag == M3UA_PARAM_PROTOCOL_DATA:
                protocol_data = param.value
                self.logger.info(f"  -> This is Protocol Data parameter")
                
            elif param.tag == M3UA_PARAM_ROUTING_CONTEXT:
                routing_context = struct.unpack('!I', param.value)[0]
                self.logger.info(f"  -> This is Routing Context: {routing_context}")
            
            elif param.tag == M3UA_PARAM_NETWORK_APPEARANCE:
                na_value = struct.unpack('!I', param.value)[0] if len(param.value) >= 4 else 0
                self.logger.info(f"  -> This is Network Appearance: {na_value}")
            
            else:
                self.logger.info(f"  -> Unknown/Other parameter type")

            offset += param_len

        if not protocol_data:
            self.logger.error("No Protocol Data found in M3UA message")
            return

        self.logger.info(f"Protocol Data: {protocol_data.hex()}")

        # Find the actual MTP3 header - look for SIO byte pattern
        mtp3_offset = None
        self.logger.info("Searching for MTP3 header in Protocol Data...")
        
        for i in range(len(protocol_data) - 5):
            # Look for SIO pattern: service indicator 3 (SCCP) with network indicator
            sio_candidate = protocol_data[i]
            si = sio_candidate & 0x0F  # Service Indicator (lower 4 bits)
            ni = (sio_candidate >> 4) & 0x03  # Network Indicator (bits 4-5)
            
            self.logger.debug(f"  Offset {i}: byte=0x{sio_candidate:02X}, SI={si}, NI={ni}")
            
            if si == 3:  # SCCP Service Indicator
                mtp3_offset = i
                self.logger.info(f"  Found potential MTP3 header at offset {i}")
                break

        if mtp3_offset is None:
            # Fallback: try common fixed offsets
            for fallback_offset in [8, 12, 16]:
                if fallback_offset < len(protocol_data):
                    sio_candidate = protocol_data[fallback_offset]
                    si = sio_candidate & 0x0F
                    if si == 3:
                        mtp3_offset = fallback_offset
                        self.logger.info(f"  Using fallback MTP3 offset: {fallback_offset}")
                        break
        
        if mtp3_offset is None:
            self.logger.error("Could not find MTP3 header in Protocol Data")
            return

        # Parse MTP3 header
        if len(protocol_data) >= mtp3_offset + 5:
            sio = protocol_data[mtp3_offset]
            dpc = struct.unpack('<H', protocol_data[mtp3_offset+1:mtp3_offset+3])[0]  # Little Endian
            opc = struct.unpack('<H', protocol_data[mtp3_offset+3:mtp3_offset+5])[0]  # Little Endian
            
            ni = (sio >> 4) & 0x03
            si = sio & 0x0F
            
            self.logger.info(f"MTP3 Header (at offset {mtp3_offset}):")
            self.logger.info(f"  SIO: 0x{sio:02X} (NI={ni}, SI={si})")
            self.logger.info(f"  DPC: {dpc} (0x{dpc:04X})")
            self.logger.info(f"  OPC: {opc} (0x{opc:04X})")
            
            # Extract SCCP data (after MTP3 header)
            sccp_data = protocol_data[mtp3_offset + 5:]
            self.logger.info(f"SCCP Data: {len(sccp_data)} bytes")
            self.logger.debug(f"SCCP Data: {sccp_data.hex()}")
            
            if len(sccp_data) > 0:
                sccp_type = sccp_data[0]
                self.logger.info(f"SCCP Message Type: 0x{sccp_type:02X}")
                
                # Map SCCP message types to names
                sccp_type_names = {
                    0x09: 'UDT (Unitdata)',
                    0x0A: 'UDTS (Unitdata Service)',
                    0x11: 'XUDT (Extended Unitdata)',
                    0x12: 'XUDTS (Extended Unitdata Service)'
                }
                
                type_name = sccp_type_names.get(sccp_type, f'Unknown (0x{sccp_type:02X})')
                self.logger.info(f"SCCP Message Type Name: {type_name}")
                
                if sccp_type == SCCP_UDT or sccp_type == 0x11:  # UDT or XUDT
                    self.handle_sccp_udt(sccp_data, opc, dpc, conn, addr)
                else:
                    self.logger.warning(f"Unsupported SCCP message type: 0x{sccp_type:02X} ({type_name})")
        else:
            self.logger.error("Protocol data too short for MTP3 header at calculated offset")

      except Exception as e:
        self.logger.error(f"Error in handle_m3ua_data: {e}")
        import traceback
        self.logger.error(f"Traceback: {traceback.format_exc()}")
      finally:
        self.logger.info("=" * 60)
    

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
        """Handle client connection with enhanced error handling"""
        try:
            self.logger.info(f"SCTP association established with {addr[0]}:{addr[1]}")
            
            while self.running:
                try:
                    data = conn.recv(4096)
                    if not data:
                        self.logger.info(f"Client {addr[0]}:{addr[1]} disconnected")
                        break
                    
                    self.logger.debug(f"Raw SCTP DATA from {addr[0]}:{addr[1]} - {len(data)} bytes: {data.hex()}")
                    
                    # Parse M3UA message
                    m3ua_msg = M3UAMessage.unpack(data)
                    if m3ua_msg and m3ua_msg.version == 1:
                        self.handle_m3ua_message(m3ua_msg, conn, addr)
                    else:
                        self.logger.warning(f"Invalid M3UA message from {addr[0]}:{addr[1]}")
                        if m3ua_msg:
                            self.logger.warning(f"  Version: {m3ua_msg.version}, expected: 1")
                    
                except socket.timeout:
                    continue
                except socket.error as e:
                    self.logger.warning(f"Socket error from {addr[0]}:{addr[1]}: {e}")
                    break
                except Exception as e:
                    self.logger.error(f"Unexpected error handling data from {addr[0]}:{addr[1]}: {e}")
                    break
        
        except Exception as e:
            self.logger.error(f"Error in client handler for {addr[0]}:{addr[1]}: {e}")
        finally:
            conn_key = f"{addr[0]}:{addr[1]}"
            if conn_key in self.asp_states:
                del self.asp_states[conn_key]
                self.logger.info(f"Removed ASP state for {conn_key}")
            
            try:
                conn.close()
            except:
                pass
            self.logger.info(f"Connection closed with {addr[0]}:{addr[1]}")
    
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
            
            self.logger.info("=" * 60)
            self.logger.info(f"Enhanced MAP SIGTRAN Server listening on {self.host}:{self.port}")
            self.logger.info("Features:")
            self.logger.info("  - MAP SRI-SM request handling")
            self.logger.info("  - SRI-SM response with NNN and IMSI")
            self.logger.info("  - Comprehensive protocol logging")
            self.logger.info("  - M3UA/SCCP/TCAP/MAP stack support")
            self.logger.info("=" * 60)
            
            self.running = True
            
            while self.running:
                try:
                    conn, addr = self.socket.accept()
                    self.logger.info(f"New SCTP connection from {addr[0]}:{addr[1]}")
                    
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                
                except socket.timeout:
                    continue  # Just continue waiting for connections
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
        self.logger.info("Stopping Enhanced MAP SIGTRAN server...")
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
        self.logger.info("Enhanced MAP SIGTRAN server stopped")

def main():
    """Main function with enhanced startup information"""
    print("=" * 60)
    print("Enhanced MAP SIGTRAN Server with SRI-SM Support")
    print("Handles Send Routing Info for Short Message requests")
    print("Responds with Network Node Number (NNN) and IMSI")
    print("=" * 60)
    print()
    
    server = MAPSIGTRANServer()
    
    try:
        print("Starting Enhanced MAP SIGTRAN Server...")
        print("Configuration:")
        print(f"  Local GT (HLR): {CONFIG['local_gt']}")
        print(f"  Local PC: {CONFIG['local_pc']}")
        print(f"  Remote GT: {CONFIG['remote_gt']}")
        print(f"  Remote PC: {CONFIG['remote_pc']}")
        print(f"  Route Context: {CONFIG['route_context']}")
        print(f"  MSC GT (NNN): {CONFIG['msc_gt']}")
        print(f"  VLR GT: {CONFIG['vlr_gt']}")
        print()
        print("Features:")
        print("  ✓ Enhanced MSISDN parsing from TCAP")
        print("  ✓ Proper ASN.1 encoding for MAP responses")
        print("  ✓ IMSI generation based on MSISDN")
        print("  ✓ Comprehensive logging to file and console")
        print("  ✓ Error handling and troubleshooting support")
        print()
        print("Logs are written to: map_sigtran_server.log")
        print("Press Ctrl+C to stop")
        print("=" * 60)
        print()
        
        server.start()
        
    except KeyboardInterrupt:
        print("\nShutdown requested...")
        server.stop()
    except Exception as e:
        print(f"Fatal error: {e}")
        server.stop()

if __name__ == "__main__":
    main()
    
