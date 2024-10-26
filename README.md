A Demo of QUIC_Attack.

Based on aioquic 0.9.20 & lsquic 3.0.4.

For both 2 quic version, please change the cid length config to 20.
For aioquic: src/aioquic/quic/configuration.py
Change "connection_id_length" to 20 and in "class QuicConfiguration" add "QuicProtocolVersion.VNRF".
For lsquic: lsquic/include/lsquic.h
Change the macro "LSQUIC_DF_SCID_LEN" to "MAX_CID_LEN" or at least 20.

You have to generate certificates at first.

Run the code with sudo and it should be okay.

The QShield is protected and cannot be open sourced.

You can use tools like iptables to capture the attack vectors and save in pcap files.

Here are 2 pcap files that show the experiment. You may check it in Wireshark.
