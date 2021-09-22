# sctpunbundle
Splits SCTP chunks into separate frames in a PCAP file. 
Can read both from PCAP and PCAP-NG file format.
Write only to PCAP.

```
Usage: sctpunbundle <input file> <out file>
```

## How it works.
Read frame from input file:
- If frame does not contains SCTP layer, write frame to output file without changes
- If frame has SCTP layer and SCTP checksum is correct, split chunks into different frame, write to output file and update checksum
(checksum depends on original frame: CRC32 or Adler32)
- If frame has SCTP layer and SCTP checksum is incorrect, split chunks into different frames, write to output file but checksum value is 0x00000000
