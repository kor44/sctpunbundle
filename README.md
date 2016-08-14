# sctpunbundle
Splits SCTP chunks into separate frames in a PCAP file. PCAP-NG file format not supported.

```
Usage: sctpunbundle <input file> <out file>
```

##How it works.
Read frame from input file:
- Frame does not contains SCTP layer, write to output file as is
- Frame has SCTP layer and SCTP checksum is correct, write chunks as different frames to output file and update checksum
(checksum depends on original CRC32 or Adlre32)
- Frame has SCTP layer and SCTP checksum is incorrect, write chunks as different frames but checksum is 0x00000000
