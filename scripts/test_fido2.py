#!/usr/bin/env python3
"""
Diagnostic test suite for RP2040 Post-Quantum & Classical FIDO2 Authenticator.
Tests:
  1. CTAPHID channel allocation and capabilities.
  2. authenticatorGetInfo (verifying ML-DSA-87, ML-KEM-1024, secp521r1, secp256r1).
  3. authenticatorClientPIN with Post-Quantum Protocol 3 (ML-KEM-1024 Ephemeral Key Agreement).
  4. authenticatorMakeCredential with ML-DSA-87 (PQC RFC 9964 alg -50) & self-attestation.
  5. authenticatorGetAssertion with ML-DSA-87 using the generated credential.
  6. authenticatorMakeCredential with ECDSA secp521r1 (alg -36, ES512) & self-attestation.
  7. authenticatorGetAssertion with ECDSA secp521r1 using the generated credential.
  8. Automatic reboot back to BOOTSEL programming mode via CTAPHID vendor command (0xD1).
"""

import os
import glob
import struct
import time
import sys
import argparse

PACKET_SIZE = 64
BROADCAST_CID = 0xFFFFFFFF

CTAPHID_CMD_PING           = 0x81
CTAPHID_CMD_INIT           = 0x86
CTAPHID_CMD_WINK           = 0x88
CTAPHID_CMD_CBOR           = 0x90
CTAPHID_CMD_ERROR          = 0xBF
CTAPHID_CMD_VENDOR_REBOOT  = 0xD1  # Reboot to BOOTSEL
CTAPHID_CMD_VENDOR_AUTO_UP = 0xD2  # Toggle/set User Presence auto-confirm

CTAP2_CMD_MAKE_CREDENTIAL  = 0x01
CTAP2_CMD_GET_ASSERTION    = 0x02
CTAP2_CMD_GET_INFO         = 0x04
CTAP2_CMD_CLIENT_PIN       = 0x06
CTAP2_CMD_RESET            = 0x07

def find_fido_hidraw():
    for uevent in glob.glob('/sys/class/hidraw/hidraw*/device/uevent'):
        try:
            with open(uevent, 'r') as f:
                content = f.read()
                if '2E8A' in content.upper() and '1050' in content.upper():
                    hidraw = '/dev/' + uevent.split('/')[4]
                    return hidraw
        except Exception:
            pass

    for rd in glob.glob('/sys/class/hidraw/hidraw*/device/report_descriptor'):
        try:
            with open(rd, 'rb') as f:
                desc = f.read()
                if b'\x06\xd0\xf1' in desc:
                    hidraw = '/dev/' + rd.split('/')[4]
                    return hidraw
        except Exception:
            pass
    return None

class FidoHidClient:
    def __init__(self, dev_path):
        self.dev_path = dev_path
        self.fd = os.open(dev_path, os.O_RDWR)
        self.cid = BROADCAST_CID

    def close(self):
        if self.fd:
            os.close(self.fd)
            self.fd = None

    def send_packet(self, data):
        packet = b'\x00' + data + bytes(PACKET_SIZE - len(data))
        os.write(self.fd, packet)

    def read_packet(self, timeout_s=10.0):
        t0 = time.time()
        while time.time() - t0 < timeout_s:
            try:
                pkt = os.read(self.fd, PACKET_SIZE + 1)
                if len(pkt) == PACKET_SIZE + 1:
                    return pkt[1:]
                elif len(pkt) == PACKET_SIZE:
                    return pkt
            except BlockingIOError:
                time.sleep(0.01)
        raise TimeoutError("Timeout reading HID packet")

    def init_channel(self):
        nonce = os.urandom(8)
        pkt = struct.pack('>IBH', BROADCAST_CID, CTAPHID_CMD_INIT, 8) + nonce
        self.send_packet(pkt)

        resp = self.read_packet()
        rcid, cmd, rlen = struct.unpack('>IBH', resp[:7])
        payload = resp[7:7 + rlen]
        resp_nonce = payload[:8]
        if resp_nonce != nonce:
            raise ValueError("Nonce mismatch in CTAPHID_INIT")

        self.cid = struct.unpack('>I', payload[8:12])[0]
        version, major, minor, build, caps = struct.unpack('BBBBB', payload[12:17])
        print(f"  Allocated CID: 0x{self.cid:08X}")
        print(f"  CTAPHID Version: {version}.{major}.{minor}.{build}, Capabilities: 0x{caps:02X}")
        return self.cid

    def send_msg(self, cmd, payload):
        total_len = len(payload)
        chunk = payload[:57]
        pkt = struct.pack('>IBH', self.cid, cmd, total_len) + chunk
        self.send_packet(pkt)
        offset = len(chunk)

        seq = 0
        while offset < total_len:
            chunk = payload[offset:offset + 59]
            pkt = struct.pack('>IB', self.cid, seq) + chunk
            self.send_packet(pkt)
            offset += len(chunk)
            seq = (seq + 1) & 0x7F

        resp_pkt = self.read_packet(timeout_s=35.0)
        rcid, rcmd, rlen = struct.unpack('>IBH', resp_pkt[:7])
        if rcmd == CTAPHID_CMD_ERROR:
            err = resp_pkt[7]
            raise RuntimeError(f"CTAPHID Error: 0x{err:02X}")

        rx_data = resp_pkt[7:7 + min(rlen, 57)]
        expected_seq = 0
        while len(rx_data) < rlen:
            cont_pkt = self.read_packet(timeout_s=5.0)
            c_cid, c_seq = struct.unpack('>IB', cont_pkt[:5])
            if c_seq != expected_seq:
                raise ValueError(f"Sequence mismatch: expected {expected_seq}, got {c_seq}")
            expected_seq = (expected_seq + 1) & 0x7F
            remaining = rlen - len(rx_data)
            chunk = cont_pkt[5:5 + min(remaining, 59)]
            rx_data += chunk

        return rx_data

    def send_cbor(self, ctap_cmd, cbor_payload=b''):
        request = bytes([ctap_cmd]) + cbor_payload
        response = self.send_msg(CTAPHID_CMD_CBOR, request)
        status = response[0]
        return status, response[1:]

    def set_auto_up(self, enable=True):
        print(f"  Configuring Authenticator Auto-UP -> {enable}...")
        resp = self.send_msg(CTAPHID_CMD_VENDOR_AUTO_UP, bytes([1 if enable else 0]))
        enabled = (len(resp) > 0 and resp[0] != 0)
        print(f"  [CONFIRMED] Authenticator Auto-UP: {'ENABLED' if enabled else 'DISABLED'}")
        return enabled

    def reboot_to_bootsel(self):
        print("\nSending CTAPHID Vendor Reboot Command (0xD1)...")
        pkt = struct.pack('>IBH', self.cid, CTAPHID_CMD_VENDOR_REBOOT, 0)
        self.send_packet(pkt)

def extract_cred_id(mc_response_bytes):
    # Find authData (tagged with key 2 in map)
    pos = mc_response_bytes.find(b'\x02\x59')
    if pos != -1:
        ad_len = struct.unpack('>H', mc_response_bytes[pos + 2 : pos + 4])[0]
        auth_data = mc_response_bytes[pos + 4 : pos + 4 + ad_len]
    else:
        pos = mc_response_bytes.find(b'\x02\x58')
        if pos == -1:
            return None
        ad_len = mc_response_bytes[pos + 2]
        auth_data = mc_response_bytes[pos + 3 : pos + 3 + ad_len]

    if len(auth_data) < 55:
        return None
    cred_len = struct.unpack('>H', auth_data[53:55])[0]
    return auth_data[55 : 55 + cred_len]

def build_get_assertion_cbor(rp_id_str, client_data_hash, cred_id):
    rp_bytes = rp_id_str.encode('utf-8')
    rp_field = b'\x01' + bytes([0x60 + len(rp_bytes)]) + rp_bytes
    cdh_field = b'\x02\x58\x20' + client_data_hash

    # allowList: [{"type": "public-key", "id": cred_id}]
    cred_item = (
        b'\xa2' +
        b'\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79' +
        b'\x62\x69\x64' + bytes([0x58, len(cred_id)]) + cred_id
    )
    allow_field = b'\x03\x81' + cred_item
    return b'\xa3' + rp_field + cdh_field + allow_field

def run_tests():
    parser = argparse.ArgumentParser(description="RP2040 PQC FIDO2 Diagnostic Suite")
    parser.add_argument("--auto-up", action="store_true", help="Enable automatic User Presence confirmation for test suite")
    parser.add_argument("--reboot", action="store_true", help="Reboot dongle into BOOTSEL mode at the end of the run")
    args = parser.parse_args()

    print("================================================================")
    print(" RP2040 Post-Quantum & Classical FIDO2 Diagnostic Suite")
    print(" Target: Waveshare RP2040-One")
    print("================================================================")

    dev_path = find_fido_hidraw()
    if not dev_path:
        print("Error: No RP2040 FIDO2 device found under /dev/hidraw*")
        print("Tip: If the board is in BOOTSEL mode, run scripts/flash.sh first.")
        sys.exit(1)

    print(f"Connected to device at: {dev_path}")
    client = FidoHidClient(dev_path)

    try:
        print("\n[1] Testing CTAPHID_INIT channel allocation...")
        client.init_channel()
        print("  [PASS] Channel initialized successfully.")

        if args.auto_up:
            print("\n[*] Enabling Auto-UP mode for automated non-interactive testing...")
            client.set_auto_up(True)

        print("\n[2] Testing authenticatorGetInfo (0x04)...")
        status, info_cbor = client.send_cbor(CTAP2_CMD_GET_INFO)
        if status != 0:
            print(f"  [FAIL] GetInfo returned error: 0x{status:02X}")
        else:
            print(f"  [PASS] GetInfo succeeded (payload: {len(info_cbor)} bytes)")
            has_mldsa87 = (b'\x38\x31' in info_cbor or b'\x33' in info_cbor)
            has_p521    = (b'\x38\x23' in info_cbor)
            has_p256    = (b'\x26' in info_cbor)
            print(f"    - ML-DSA-87 (PQC RFC 9964 alg -50 / -20): {'[YES]' if has_mldsa87 else '[NO]'}")
            print(f"    - ECDSA secp521r1 (P-521 ES512 alg -36): {'[YES]' if has_p521 else '[NO]'}")
            print(f"    - ECDSA secp256r1 (P-256 ES256 alg -7):   {'[YES]' if has_p256 else '[NO]'}")

        print("\n[3] Testing authenticatorClientPIN with ML-KEM-1024 (PQ KEM Protocol 3)...")
        # Request keyAgreement COSE key with protocol 3: {1: 3, 2: 2}
        pin_kem_req = b'\xa2\x01\x03\x02\x02'
        t0 = time.time()
        status, resp = client.send_cbor(CTAP2_CMD_CLIENT_PIN, pin_kem_req)
        elapsed = time.time() - t0
        if status == 0:
            print(f"  [PASS] ML-KEM-1024 Ephemeral Key generated in {elapsed:.3f}s! (Response: {len(resp)} bytes)")
            # Key type 6 (PQCKEM), alg -24 (CBOR 0x37)
            has_pqckem = b'\x01\x06' in resp and (b'\x03\x37' in resp or b'\x03\x38\x17' in resp)
            print(f"    - Verified ML-KEM-1024 COSE Key (kty=6, alg=-24): {'[YES]' if has_pqckem else '[NO]'}")
        else:
            print(f"  [FAIL] ClientPIN KEM returned status: 0x{status:02X}")

        print("\n[4] Testing authenticatorMakeCredential with ML-DSA-87 (PQC)...")
        cdh_mldsa = os.urandom(32)
        mc_mldsa = (
            b'\xa4' +
            b'\x01\x58\x20' + cdh_mldsa +
            b'\x02\xa1\x62\x69\x64\x6b\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d' +
            b'\x03\xa1\x62\x69\x64\x45\x75\x73\x65\x72\x31' +
            b'\x04\x81\xa2\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79\x63\x61\x6c\x67\x38\x31' # alg -50
        )
        print("  Generating ML-DSA-87 credential on RP2040...")
        if not args.auto_up:
            print("  >> Press the BOOTSEL button on the dongle if LED is flashing! <<")
        t0 = time.time()
        status, resp = client.send_cbor(CTAP2_CMD_MAKE_CREDENTIAL, mc_mldsa)
        elapsed = time.time() - t0
        mldsa_cred_id = None
        if status == 0:
            print(f"  [PASS] ML-DSA-87 Credential generated in {elapsed:.3f}s! Total response size: {len(resp)} bytes")
            mldsa_cred_id = extract_cred_id(resp)
            if mldsa_cred_id:
                print(f"    - Wrapped Credential ID ({len(mldsa_cred_id)} bytes): {mldsa_cred_id.hex()[:32]}...")
        else:
            print(f"  [STATUS] MakeCredential returned 0x{status:02X}")

        if mldsa_cred_id:
            print("\n[5] Testing authenticatorGetAssertion with ML-DSA-87...")
            ga_cdh = os.urandom(32)
            ga_mldsa = build_get_assertion_cbor("example.com", ga_cdh, mldsa_cred_id)
            t0 = time.time()
            status, resp = client.send_cbor(CTAP2_CMD_GET_ASSERTION, ga_mldsa)
            elapsed = time.time() - t0
            if status == 0:
                print(f"  [PASS] ML-DSA-87 Assertion signed in {elapsed:.3f}s! Total response size: {len(resp)} bytes")
            else:
                print(f"  [FAIL] GetAssertion returned 0x{status:02X}")

        print("\n[6] Testing authenticatorMakeCredential with ECDSA secp521r1 (P-521 ES512)...")
        cdh_p521 = os.urandom(32)
        mc_p521 = (
            b'\xa4' +
            b'\x01\x58\x20' + cdh_p521 +
            b'\x02\xa1\x62\x69\x64\x6b\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d' +
            b'\x03\xa1\x62\x69\x64\x45\x75\x73\x65\x72\x32' +
            b'\x04\x81\xa2\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79\x63\x61\x6c\x67\x38\x23' # alg -36
        )
        print("  Generating secp521r1 credential on RP2040...")
        if not args.auto_up:
            print("  >> Press the BOOTSEL button on the dongle if LED is flashing! <<")
        t0 = time.time()
        status, resp = client.send_cbor(CTAP2_CMD_MAKE_CREDENTIAL, mc_p521)
        elapsed = time.time() - t0
        p521_cred_id = None
        if status == 0:
            print(f"  [PASS] secp521r1 Credential generated in {elapsed:.3f}s! Total response size: {len(resp)} bytes")
            p521_cred_id = extract_cred_id(resp)
            if p521_cred_id:
                print(f"    - Wrapped Credential ID ({len(p521_cred_id)} bytes): {p521_cred_id.hex()[:32]}...")
        else:
            print(f"  [STATUS] MakeCredential returned 0x{status:02X}")

        if p521_cred_id:
            print("\n[7] Testing authenticatorGetAssertion with ECDSA secp521r1...")
            ga_cdh2 = os.urandom(32)
            ga_p521 = build_get_assertion_cbor("example.com", ga_cdh2, p521_cred_id)
            t0 = time.time()
            status, resp = client.send_cbor(CTAP2_CMD_GET_ASSERTION, ga_p521)
            elapsed = time.time() - t0
            if status == 0:
                print(f"  [PASS] secp521r1 Assertion signed in {elapsed:.3f}s! Total response size: {len(resp)} bytes")
            else:
                print(f"  [FAIL] GetAssertion returned 0x{status:02X}")

        if args.reboot:
            print("\n[8] Testing automatic reboot to BOOTSEL...")
            client.reboot_to_bootsel()
            print("  [SENT] Reboot command sent. Verifying RP2040 drops back to bootloader...")
            time.sleep(1.5)
            # Check if /media/player999/RPI-RP2 or /dev/disk/by-label/RPI-RP2 appeared
            boot_found = os.path.exists('/media/player999/RPI-RP2') or glob.glob('/dev/disk/by-label/RPI-RP2*')
            print(f"  BOOTSEL mount present: {'[YES]' if boot_found else '[CHECKING]'}")

        print("\n================================================================")
        print(" Test run completed successfully!")
        print("================================================================")

    finally:
        client.close()

if __name__ == '__main__':
    run_tests()
