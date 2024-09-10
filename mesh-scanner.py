"""Quick'n'dirty Meshtastic scanner.

This scanner loops on every region channels with different configurations,
sends a ping message and waits for a repeated message. If a message is repeated,
it logs the information of the repeater node.
"""
import sys
import argparse
from random import randint
from whad.device import WhadDevice
from whad.phy.connector.lora import LoRa
from tastic_helpers import MeshChannelConfiguration, RegionEU868, MeshtasticHdr

# Create our LoRa transceiver
transceiver = LoRa(WhadDevice.create('uart0'))
transceiver.preamble_length = 8
transceiver.syncword = b"\xb4\x24"
transceiver.enable_crc(True)
transceiver.enable_explicit_mode(True)


# Loop on possible configurations
region = RegionEU868
for config in MeshChannelConfiguration.presets(region):
    if 1:
        sys.stdout.write("Scanning %s ch. %d ..." % (config.preset, config.channel+1))
        sys.stdout.flush()

        # Configure our transceiver
        transceiver.set_frequency(config.freq)
        transceiver.sf = config.sf
        transceiver.bw = int(config.bw)
        transceiver.cr = config.cr

        # Start hardware
        transceiver.enable_synchronous(True)
        transceiver.start()

        # Generate a random sender addr and packet id
        sender_addr = randint(0, 0x100000000)
        packet_id = randint(0, 0x100000000)

        # Build a Meshtastic packet (ping)
        ping_pkt = MeshtasticHdr(
            sender_addr=sender_addr,
            dest_addr=0xffffffff,
            packet_id=packet_id,
            hop_start=3,
            hop_limit=3,
            channel_hash=127
        )/b"PING"

        # Send this packet
        transceiver.send(bytes(ping_pkt))

        # Wait for someone to repeat it ...
        response = transceiver.wait_packet(5.0)
        if response is not None:
            sys.stdout.write("\r[%s] channel num %d (%3.3f MHz) - FOUND\n" % (
                config.preset,
                config.channel+1,
                config.freq/1000000
            ))
        else:
            sys.stdout.write("\r")
        sys.stdout.flush()

        # Stop transceiver
        transceiver.stop()
