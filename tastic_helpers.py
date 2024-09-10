import base64
import binascii

from scapy.fields import *
from scapy.packet import Packet

from math import floor
from meshtastic.protobuf import config_pb2, apponly_pb2, channel_pb2, localonly_pb2, mesh_pb2, portnums_pb2
from struct import pack
from Crypto.Cipher import AES
from Crypto.Util import Counter

# Define our Meshtastic message in scapy
class MeshtasticHdr(Packet):
    name = "MeshtasticHdr "
    fields_desc=[
        XLEIntField("dest_addr", 0xffffffff),
        XLEIntField("sender_addr", 0xffffffff),
        XLEIntField("packet_id", 0),
        BitField("hop_limit", 3, 3),
        BitField("want_ack", 0, 1),
        BitField("via_mqtt", 0, 1),
        BitField("hop_start", 0, 3),
        ByteField("channel_hash", 0),
        ShortField("rfu", 0),
    ]

class RegionUS:
    freq_start = 902.0
    freq_end = 928.0
    duty_cycle = 100
    spacing = 0
    power_max = 30
    audio_permitted = True
    freq_switching = False
    wide_lora = False

class RegionEU868:
    freq_start = 869.4
    freq_end = 869.65
    duty_cycle = 10
    spacing = 0
    power_max = 27
    audio_permitted = False
    freq_switching = False
    wide_lora = False


def hash(channel):
    """Meshtastic channel name hashing algorithm

    >> original algorithm from meshtastic firmware source code

    uint32_t hash(const char *str)
    {
        uint32_t hash = 5381;
        int c;

        while ((c = *str++) != 0)
            hash = ((hash << 5) + hash) + (unsigned char)c; /* hash * 33 + c */

        return hash;
    }
    """
    h = 5381
    for i in range(len(channel)):
        h = (((h << 5) + h)&0xffffffff) + ord(channel[i])
    return h

def chan_hash(name, psk):
    """Compute chan hash (8 bit) from channel name and psk
    """
    buffer = name + psk
    h = 0
    for x in buffer:
        h ^= x
    return h


class MeshChannelConfiguration:
    """Mesh channel configuration
    """

    PRESETS = {
        config_pb2.Config.LoRaConfig.ModemPreset.SHORT_FAST: {
            'bw': (812.5, 250),
            'cr': 45,
            'sf': 7
        },
        config_pb2.Config.LoRaConfig.ModemPreset.SHORT_SLOW: {
            'bw': (812.5, 250),
            'cr': 45,
            'sf': 8             
        },
        config_pb2.Config.LoRaConfig.ModemPreset.MEDIUM_FAST: {
            'bw': (812.5, 250),
            'cr': 45,
            'sf': 9          
        },
        config_pb2.Config.LoRaConfig.ModemPreset.MEDIUM_SLOW: {
            'bw': (812.5, 250),
            'cr': 45,
            'sf': 10            
        },
        config_pb2.Config.LoRaConfig.ModemPreset.LONG_MODERATE: {
            'bw': (406.25, 125),
            'cr': 48,
            'sf': 11            
        },
        config_pb2.Config.LoRaConfig.ModemPreset.LONG_SLOW: {
            'bw': (406.25, 125),
            'cr': 48,
            'sf': 12            
        },
        config_pb2.Config.LoRaConfig.ModemPreset.VERY_LONG_SLOW: {
            'bw': (203.125, 62.5),
            'cr': 48,
            'sf': 12              
        }

    }


    def __init__(self):
        """Initialize an empty channel configuration
        """
        self.freq = 0
        self.cr = 44
        self.sf = 7
        self.bw = 250000
        self.psk = b""
        self.hash = 0

    def __str__(self):
        """Meshtastic channel configuration representation
        """
        psk = self.psk.hex()
        return f"MeshChannelConfiguration(freq={self.freq}, cr={self.cr}, sf={self.sf}, bw={self.bw}, psk={psk}, chan_hash={self.hash})"

    def __repr__(self):
        """Meshtastic channel configuration
        """
        return str(self)

    @staticmethod
    def parse_url(url) -> apponly_pb2.ChannelSet:
        """Parse Meshtastic channel share URL
        """
        # URLs are of the form https://meshtastic.org/d/#{base64_channel_set}
        # Split on '/#' to find the base64 encVoded channel settings
        splitURL = url.split("/#")
        b64 = splitURL[-1]

        # We normally strip padding to make for a shorter URL, but the python parser doesn't like
        # that.  So add back any missing padding
        # per https://stackoverflow.com/a/9807138
        missing_padding = len(b64) % 4
        if missing_padding:
            b64 += "=" * (4 - missing_padding)

        decodedURL = base64.urlsafe_b64decode(b64)
        channel = apponly_pb2.ChannelSet()
        channel.ParseFromString(decodedURL)
        print(channel)

        # Deduce LoRa configuration from channel settings
        bw = 250
        cr = 45
        sf = 11
        if channel.lora_config.use_preset:
            modem_preset = channel.lora_config.modem_preset
            if modem_preset in MeshChannelConfiguration.PRESETS:
                lora_cfg = MeshChannelConfiguration.PRESETS[modem_preset]
        else:
            lora_cfg = {
                'bw': (channel.lora_config.bandwidth, channel.lora_config.bandwidth),
                'cr': channel.lora_config.coding_rate,
                'sf': channel.lora_config.spread_factor
            }

        # Determine bandwidth based on region
        region = RegionEU868

        bw = lora_cfg['bw'][0] if region.wide_lora else lora_cfg['bw'][1]
        cr = lora_cfg['cr']
        sf = lora_cfg['sf']

        # Adjust bandwidth
        if bw == 31:
            bw = 31.25
        if bw == 62:
            bw = 62.5
        if bw == 200:
            bw = 203.125
        if bw == 400:
            bw = 406.25
        if bw == 800:
            bw = 812.5
        if bw == 1600:
            bw = 1625.0

        if (region.freq_end - region.freq_start) < (bw / 1000):
            print('fallback')

        # Compute channel frequency based on channel name
        num_channels = floor((region.freq_end - region.freq_start) / (region.spacing + (bw / 1000)))
        channel_num = hash(channel.settings[0].name) % num_channels
        freq = region.freq_start + (bw / 2000) + (channel_num * (bw / 1000))

        # Configure channel
        print(channel.settings[0].name.encode("utf-8"))
        channel_config = MeshChannelConfiguration()
        channel_config.freq = int(freq*1000000)
        channel_config.cr = cr
        channel_config.sf = sf
        channel_config.bw = bw*1000
        channel_config.psk = channel.settings[0].psk
        channel_config.hash = chan_hash(channel.settings[0].name.encode("utf-8"), channel.settings[0].psk)

        # Return configuration
        return channel_config


###
#
# Cryptographic primitives
#
###

def int_of_string(s):
    return int(binascii.hexlify(s), 16)


# implement some encryption/decryption
def init_nonce(sender_addr, packet_id):
    """Init nonce
    """
    nonce = pack("<Q", packet_id) + pack("<Q", sender_addr)
    return nonce

def encrypt_data(sender_addr, packet_id, key, data):
    """Encrypt a Meshtastic payload
    """
    nonce = init_nonce(sender_addr, packet_id)
    ctr = Counter.new(128, little_endian=False, initial_value=int_of_string(nonce))
    cipher = AES.new(key=key, mode=AES.MODE_CTR, counter=ctr)
    result = cipher.encrypt(data)
    return result

def decrypt_data(sender_addr, packet_id, key, data):
    """Decrypt a Meshtastic payload
    """
    return encrypt_data(sender_addr, packet_id, key, data)
