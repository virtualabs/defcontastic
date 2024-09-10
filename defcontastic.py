import sys
from random import randint
from time import time, sleep
from threading import Lock

# Import our channel configuration and Meshtastic crypto helpers, as well as some
# dedicated scapy layer
from tastic_helpers import MeshChannelConfiguration, encrypt_data, decrypt_data, MeshtasticHdr

# Import specific parts of Meshtastic python library (protobuf)
from meshtastic.protobuf.mesh_pb2 import Data
from meshtastic.protobuf.portnums_pb2 import PortNum
from meshtastic.protobuf.mesh_pb2 import User

# Import WHAD LoRa connector
from whad.device import WhadDevice
from whad.phy.connector.lora import LoRa

class Meshtastic(LoRa):
    """Meshtastic Connector
    """

    def __init__(self, device, channel):
        self.key = channel.psk
        super().__init__(device)
        self.set_frequency(channel.freq)
        self.sf = channel.sf
        self.cr = channel.cr
        self.bw = channel.bw
        self.chan_hash = channel.hash
        self.preamble_length = 8
        self.syncword = b"\xb4\x24"
        self.enable_crc(True)
        self.enable_explicit_mode(True)
        self.invert_iq = False
        self.packets_id = {}
        self.users = {}
        self.__monitor = None

    def set_monitor(self, monitor):
        self.__monitor = monitor

    def register_user(self, node):
        """Register a user node
        """
        address = int(node.id[1:],16)
        if address not in self.users:
            self.users[address] = node.short_name

    def find_user(self, address):
        if address in self.users:
            return self.users[address]
        else:
            return None

    def find_user_by_name(self, name):
        for address in self.users:
            if self.users[address] == name:
                return address
        return None

    def add_packet(self, packet_id):
        # Add packet if required
        if packet_id not in self.packets_id:
            self.packets_id[packet_id] = time()
        # Remove packets that are too old
        remove_list = []
        for pid in self.packets_id:
            if (time() - self.packets_id[pid]) > 3*60:
                remove_list.append(pid)
        for pid in remove_list:
            del self.packets_id[pid]

    def has_seen_packet(self, packet_id):
        return packet_id in self.packets_id

    def decrypt_data(self, sender_addr, packet_id, key, data):
        """Decrypt decryption
        """
        return decrypt_data(sender_addr, packet_id, key, data)

    def encrypt_data(self, sender_addr, packet_id, key, data):
        """Data encryption
        """
        return encrypt_data(sender_addr, packet_id, key, data)

    def send_message(self, sender_addr, message, dest=None):
        # craft a Data payload
        data = Data(
            portnum=PortNum.TEXT_MESSAGE_APP,
            request_id=randint(0, 0x100000),
            payload = message.encode("utf-8")
        )
        packet_id = randint(0, 0xffffffff)
        payload = self.encrypt_data(sender_addr, packet_id, self.key, data.SerializeToString())
        frame = MeshtasticHdr(
            sender_addr=sender_addr,
            dest_addr=0xffffffff if dest is None else dest,
            packet_id=packet_id,
            hop_start=3,
            hop_limit=3,
            channel_hash=self.chan_hash,
            via_mqtt=0
        )/payload
        self.send(bytes(frame))

    def on_packet(self, packet):
        try:
            frame = MeshtasticHdr(bytes(packet))
            decrypted = self.decrypt_data(frame.sender_addr, frame.packet_id,
                                        self.key, bytes(frame.payload))
            data = Data()
            data.ParseFromString(decrypted)
            if data.portnum == PortNum.TEXT_MESSAGE_APP:
                if not self.has_seen_packet(frame.packet_id):
                    self.add_packet(frame.packet_id)

                    # Solve user name from address
                    sender_name = self.find_user(frame.sender_addr)
                    dest_name = self.find_user(frame.dest_addr)
                    if self.__monitor is not None:
                        self.__monitor.show_message(
                            frame.sender_addr,
                            sender_name,
                            frame.dest_addr,
                            dest_name,
                            data.payload
                        )
                    sleep(.5)
                    self.send(bytes(frame))
            elif data.portnum == PortNum.NODEINFO_APP:
                # Process node info
                node = User()
                node.ParseFromString(data.payload)
                self.register_user(node)
        except Exception as e:
            print(e)
            pass

class MeshtasticMonitor:
    """Meshtastic discussions monitor
    """

    def __init__(self):
        self.__lock = Lock()
        sys.stdout.write('> ')


    def show_message(self, sender_addr, sender_nick, dest_addr, dest_nick, payload):
        self.__lock.acquire()
        message = payload.decode("utf-8")
        sender_desc = f"{sender_addr:08x}" if sender_nick is None else f"{sender_nick}@{sender_addr:08x}"
        dest_desc = f"{dest_addr:08x}" if dest_nick is None else f"{dest_nick}@{dest_addr:08x}"
        if dest_addr == 0xffffffff:
            print(f'\r[{sender_desc}] {message}')
        else:
            print(f"\r[{sender_desc} -> {dest_desc}] {message}")
        sys.stdout.write('> ')
        sys.stdout.flush()
        self.__lock.release()

    def process_input(self, input):
        self.__lock.acquire()
        sys.stdout.write('\r> ' + input + '\r\n')
        sys.stdout.flush()
        self.__lock.release()

# pick a random ID
my_addr = randint(0, 0xffffff00)
#my_addr = 0x06caff30
print(f"my address: {my_addr:08x}")

# DEFCONtastic channel:
# url = "https://meshtastic.org/e/#CjISIDhLvMAdwCLRgb82uGEh4fuWty5Vv3Qifp1q-0jWTLGhGgpERUZDT05uZWN0OgIIDRIRCAEQBjgBQANIAVAeaAHABgE"
url = "https://meshtastic.org/e/#CjASIIW2KloY_VOn3wvMzw38sXX_8MTL7ewRiGDu0d6kE4vAGgZGcmFuY2UoATABOgASEQgBEAYYBTgDQANIAVAbwAYB"
channel_config = MeshChannelConfiguration.parse_url(url)

# Configure our LoRa transceiver
#freq, cr, sf, bw, enc_key, chan_hash = config
print("encryption key: %s" % channel_config.psk.hex())

monitor = MeshtasticMonitor()

sniffer = Meshtastic(WhadDevice.create("uart0"), channel_config)
sniffer.set_monitor(monitor)
sniffer.start()

# Wait for packet
while True:
    text = input()
    if len(text) > 0:
        # Are we sending a DM ?
        if text[0] == '@':
            try:
                # Identify target user
                tokens = text.split(' ')
                dest_name = tokens[0][1:]
                dest_addr = sniffer.find_user(dest_name)
                if dest_addr is None:
                    dest_addr = int(tokens[0][1:], 16)

                # Send message
                message = ' '.join(tokens[1:])
                sniffer.send_message(my_addr, message, dest=dest_addr)
            except ValueError:
                # On error, send message as-is
                sniffer.send_message(my_addr, text)
        else:
            sniffer.send_message(my_addr, text)
