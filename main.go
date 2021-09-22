package main

import (
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"hash/crc32"
	"io"
	"os"

	"github.com/bobziuchkovski/writ"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/kor44/pcapng"
)

type DeChunk struct {
}

const (
	IPv4HeaderLength = 20
)

type Parser struct {
	eth     layers.Ethernet
	dot1q   layers.Dot1Q
	ip4     layers.IPv4
	ip6     layers.IPv6
	b       gopacket.SerializeBuffer
	decoded []gopacket.LayerType
	*gopacket.DecodingLayerParser
}

func NewParser() *Parser {
	var p Parser
	p.b = gopacket.NewSerializeBuffer()
	p.decoded = []gopacket.LayerType{}
	p.DecodingLayerParser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &p.eth, &p.dot1q, &p.ip4, &p.ip6)
	return &p

}

type packetReader interface {
	LinkType() layers.LinkType
	ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error)
}

func main() {
	dechunker := &DeChunk{}
	cmd := writ.New("sctpunbundle", dechunker)
	cmd.Help.Usage = "Usage: sctpunbundle <input file> <out file>"
	cmd.Help.Header = "Unbundle the chunks into the different frames."
	_, fileNames, err := cmd.Decode(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		cmd.WriteHelp(os.Stderr)
		return
	}

	switch {
	case len(fileNames) > 3:
		fmt.Fprintln(os.Stderr, "too much args")
		cmd.WriteHelp(os.Stderr)
		return
	case len(fileNames) < 3:
		fmt.Fprintln(os.Stderr, "need specify output file name")
		cmd.WriteHelp(os.Stderr)
		os.Exit(1)
	}

	infile, err := os.Open(fileNames[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open input file: %s", err)
		os.Exit(1)
	}
	defer infile.Close()

	var r packetReader
	r, err = pcapgo.NewReader(infile)
	if err != nil {
		infile.Seek(0, 0)
		if r, err = pcapng.NewReader(infile); err != nil {
			fmt.Fprintf(os.Stderr, "Unable to read packets: %s", err)
			os.Exit(1)
		}
	}

	outfile, err := os.Create(fileNames[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open output file: %s", err)
		os.Exit(1)
	}
	defer outfile.Close()
	wr := pcapgo.NewWriter(outfile)

	if err := wr.WriteFileHeader(0, r.LinkType()); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to write to output file: %s", err)
		os.Exit(1)
	}

	parser := NewParser()
	for packetCount := 1; ; packetCount++ {
		packet, ci, err := r.ReadPacketData()

		switch {
		case err == io.EOF:
			return
		case err != nil:
			fmt.Fprintf(os.Stderr, "Error read packet: %s", err)
			os.Exit(1)
		}

		for _, f := range unbundle(parser, packet, ci) {
			if err := wr.WritePacket(f.ci, f.data); err != nil {
				fmt.Fprintf(os.Stderr, "Unable to write packet: %s", err)
			}
		}
	}
}

type Frame struct {
	data []byte
	ci   gopacket.CaptureInfo
}

func unbundle(p *Parser, packet []byte, ci gopacket.CaptureInfo) (frames []Frame) {
	p.b.Clear()
	packetLen := len(packet)
	p.DecodeLayers(packet, &p.decoded)

	IPOptions := gopacket.SerializeOptions{}

	var sctpData []byte
	switch {
	case len(p.decoded) == 0:
		return []Frame{{packet, ci}}
	case p.decoded[len(p.decoded)-1] == layers.LayerTypeIPv4 && p.ip4.NextLayerType() == layers.LayerTypeSCTP:
		sctpData = p.ip4.Payload
		sctpDataLen := len(sctpData)
		if p.ip4.Length == uint16(sctpDataLen+IPv4HeaderLength) {
			IPOptions.FixLengths = true
		}

		// Compute checksum
		ipHeader := packet[packetLen-sctpDataLen-IPv4HeaderLength : packetLen-sctpDataLen]
		ipHeader[10] = 0
		ipHeader[11] = 0

		var csum uint32
		for i := 0; i < len(ipHeader); i += 2 {
			csum += uint32(ipHeader[i]) << 8
			csum += uint32(ipHeader[i+1])
		}
		ipChecksum := ^uint16((csum >> 16) + csum)

		if p.ip4.Checksum == ipChecksum {
			IPOptions.ComputeChecksums = true
		}
	case p.decoded[len(p.decoded)-1] == layers.LayerTypeIPv6 && p.ip6.NextLayerType() == layers.LayerTypeSCTP:
		sctpData = p.ip6.Payload
	default:
		return []Frame{{packet, ci}}

	}

	if len(sctpData) <= 12 {
		return []Frame{{packet, ci}}

	}

	crc := binary.LittleEndian.Uint32(sctpData[8:12])
	adler := binary.BigEndian.Uint32(sctpData[8:12])

	sctpData[8] = 0
	sctpData[9] = 0
	sctpData[10] = 0
	sctpData[11] = 0

	var isCRC, isAdler bool
	calcCRC := crc32.Checksum(sctpData, crc32.MakeTable(crc32.Castagnoli))
	if calcCRC == crc {
		isCRC = true
	} else { //check Adler only if CRC is wrong
		calcAdler := adler32.Checksum(sctpData)
		isAdler = (calcAdler == adler)
	}

	for _, chunk := range getChunks(sctpData[12:]) {
		p.b.Clear()

		checksum := gopacket.Payload(make([]byte, 4))
		switch {
		case isAdler:
			h := adler32.New()
			h.Write(sctpData[:12])
			h.Write(chunk)
			binary.BigEndian.PutUint32(checksum, h.Sum32())
		case isCRC:
			h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
			h.Write(sctpData[:12])
			h.Write(chunk)
			binary.LittleEndian.PutUint32(checksum, h.Sum32())
		}
		gopacket.Payload(chunk).SerializeTo(p.b, gopacket.SerializeOptions{})
		checksum.SerializeTo(p.b, gopacket.SerializeOptions{})
		gopacket.Payload(sctpData[:8]).SerializeTo(p.b, gopacket.SerializeOptions{})

		for i := len(p.decoded) - 1; i >= 0; i-- {
			switch p.decoded[i] {
			case layers.LayerTypeIPv4:
				p.ip4.SerializeTo(p.b, IPOptions)
			case layers.LayerTypeIPv6:
				p.ip6.SerializeTo(p.b, IPOptions)
			case layers.LayerTypeDot1Q:
				p.dot1q.SerializeTo(p.b, gopacket.SerializeOptions{})
			case layers.LayerTypeEthernet:
				p.eth.SerializeTo(p.b, gopacket.SerializeOptions{})
			}
		}

		ci.Length = len(p.b.Bytes())
		ci.CaptureLength = len(p.b.Bytes())

		data := make([]byte, ci.Length)
		copy(data, p.b.Bytes())
		frames = append(frames, Frame{data, ci})
	}
	return frames
}

func getChunks(data []byte) (chunks []gopacket.Payload) {
	for l := len(data); l > 0; l = len(data) {
		if l < 4 {
			chunks = append(chunks, data)
			return
		}
		length := binary.BigEndian.Uint16(data[2:4])
		actual := roundUpToNearest4(int(length))

		switch {
		case l > actual:
			chunks = append(chunks, data[0:actual])
			data = data[actual:]
		case l == actual:
			chunks = append(chunks, data)
			return
		case l < actual:
			chunks = append(chunks, data)
			return
		}
	}
	return
}

func roundUpToNearest4(i int) int {
	if i%4 == 0 {
		return i
	}
	return i + 4 - (i % 4)
}
