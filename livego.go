package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"

	"github.com/yuankang/livego/utils/is"
)

var (
	HsClientKey = []byte{
		'G', 'e', 'n', 'u', 'i', 'n', 'e', ' ', 'A', 'd', 'o', 'b', 'e', ' ',
		'F', 'l', 'a', 's', 'h', ' ', 'P', 'l', 'a', 'y', 'e', 'r', ' ',
		'0', '0', '1',
		0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8, 0x2E, 0x00, 0xD0, 0xD1,
		0x02, 0x9E, 0x7E, 0x57, 0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB,
		0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE,
	}
	HsServerKey = []byte{
		'G', 'e', 'n', 'u', 'i', 'n', 'e', ' ', 'A', 'd', 'o', 'b', 'e', ' ',
		'F', 'l', 'a', 's', 'h', ' ', 'M', 'e', 'd', 'i', 'a', ' ',
		'S', 'e', 'r', 'v', 'e', 'r', ' ',
		'0', '0', '1',
		0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8, 0x2E, 0x00, 0xD0, 0xD1,
		0x02, 0x9E, 0x7E, 0x57, 0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB,
		0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE,
	}
	HsClientKeyPart = HsClientKey[:30]
	HsServerKeyPart = HsServerKey[:36]
)

type Player struct {
}

type Publisher struct {
}

type LiveGo struct {
	Streams map[string]*Stream
}

var livego = LiveGo{make(map[string]*Stream)}

func HttpLiveHandler(w http.ResponseWriter, req *http.Request) {
	w.Write([]byte("hello live"))
}

func HttpApiHandler(w http.ResponseWriter, req *http.Request) {
	w.Write([]byte("hello api"))
}

func HttpServer() {
	http.HandleFunc("/live", HttpLiveHandler)
	http.HandleFunc("/api", HttpApiHandler)
	log.Println("HttpServer listen on :8888")
	log.Fatal(http.ListenAndServe(":8888", nil))
}

func (rc *RtmpConn) HandshakeServer() error {
	var random [(1 + 1536*2) * 2]byte

	C0C1C2 := random[:1536*2+1]
	C0 := C0C1C2[:1]
	C1 := C0C1C2[1 : 1536+1]
	C0C1 := C0C1C2[:1536+1]
	C2 := C0C1C2[1536+1:]

	S0S1S2 := random[1536*2+1:]
	S0 := S0S1S2[:1]
	S1 := S0S1S2[1 : 1536+1]
	//S0S1 := S0S1S2[:1536+1]
	S2 := S0S1S2[1536+1:]

	num, err := io.ReadFull(rc, C0C1)
	if err != nil {
		rc.log.Println(err)
		return err
	}
	rc.log.Println("recv C0C1 len=", num)

	if C0[0] != 3 {
		return fmt.Errorf("rtmp handshake version=%d invalid", C0[0])
	}

	cTime := is.U32BE(C1[0:4])
	cZero := is.U32BE(C1[4:8])
	sTime := cTime
	sZero := uint32(0x0d0e0a0d)

	S0[0] = 3
	if cZero == 0 {
		copy(S1, C2)
		copy(S2, C1)
	} else {
		// C1的key是 HsClientKeyPart
		// C1的digest是 hmac.sha256(C1key, P1+P2),P1为digest之前的部分,P2为digest之后的部分
		// S1的key是 HsServerKeyPart
		// S1的digest是 hmac.sha256(S1key, P1+P2),P1为digest之前的部分,P2为digest之后的部分
		// S2的key是 hmac.sha256(hsServerKey, C1digest)
		// S2的digest是 hmac.sha256(S2key, S2[:len(S2)-32])
		S2key, ok := HsParseC1(C1)
		if !ok {
			return fmt.Errorf("rtmp handshake C1 invalid")
		}
		HsCreateS1(S1, sTime, sZero)
		HsCreateS2(S2, S2key)
	}

	num, err = rc.Write(S0S1S2)
	if err != nil {
		rc.log.Println(err)
		return err
	}
	rc.log.Println("send S0S1S2 len=", num)

	num, err = io.ReadFull(rc, C2)
	if err != nil {
		rc.log.Println(err)
		return err
	}
	rc.log.Println("recv C2 len=", num)
	return nil
}

func HsFindDigestPos(C1 []byte, begin int) int {
	pos := 0
	for i := 0; i < 4; i++ {
		pos += int(C1[begin+i])
	}
	// 4 + 4 + 764 + 764 = 1536
	// 764key		r + 128 + r + 4
	// 764digest	4 + r + 32 + r
	// 728 = 764 - 32 - 4
	// 把pos转化为相对于C1的偏移量
	pos = (pos % 728) + begin + 4
	return pos
}

func HsCalcDigest(key, data []byte, pos int) []byte {
	h := hmac.New(sha256.New, key)
	if pos <= 0 {
		h.Write(data)
	} else {
		h.Write(data[:pos])
		h.Write(data[pos+32:])
	}
	return h.Sum(nil)
}

func HsFindDigest(C1 []byte, begin int) int {
	// 1 找到C1的digest; 2 计算C1的digest; 3 比对两个digest;
	pos := HsFindDigestPos(C1, begin)
	digest := HsCalcDigest(HsClientKeyPart, C1, pos)
	if bytes.Compare(C1[pos:pos+32], digest) != 0 {
		return -1
	}
	return pos
}

func HsParseC1(C1 []byte) ([]byte, bool) {
	var pos int
	if pos = HsFindDigest(C1, 772); pos == -1 {
		if pos = HsFindDigest(C1, 8); pos == -1 {
			return nil, false
		}
	}
	S2key := HsCalcDigest(HsServerKey, C1[pos:pos+32], -1)
	return S2key, true
}
func HsCreateS1(S1 []byte, sTime, sZero uint32) {
	is.PutU32BE(S1[0:4], sTime)
	is.PutU32BE(S1[4:8], sZero)
	rand.Read(S1[8:])
	pos := HsFindDigestPos(S1, 8)
	digest := HsCalcDigest(HsServerKeyPart, S1, pos)
	copy(S1[pos:], digest)
}
func HsCreateS2(S2, key []byte) {
	rand.Read(S2)
	pos := len(S2) - 32
	digest := HsCalcDigest(key, S2, pos)
	copy(S2[pos:], digest)
}

// split merge
func (rc *RtmpConn) ChunkMerge(c *Chunk) error {
	if c.remain != 0 && c.tmpFmt != 3 {
		return fmt.Errorf("invalid chunk, remain=%d, fmt=%d", c.remain, c.tmpFmt)
	}

	switch c.CSID {
	case 0:
		id, _ := rc.ReadUintLE(1)
		c.CSID = id + 64
	case 1:
		id, _ := rc.ReadUintLE(2)
		c.CSID = id + 64
	}

	switch c.tmpFmt {
	case 0:
		c.Fmt = c.tmpFmt
		c.Timestamp, _ = rc.ReadUintBE(3)
		c.Length, _ = rc.ReadUintBE(3)
		c.TypeID, _ = rc.ReadUintBE(1)
		c.StreamID, _ = rc.ReadUintLE(4)
		if c.Timestamp == 0xffffff {
			c.Timestamp, _ = rc.ReadUintBE(4)
			c.exted = true
		} else {
			c.exted = false
		}
		c.Done = false
		c.index = 0
		c.remain = c.Length
		c.Data = make([]byte, c.Length)
	case 1:
		c.Fmt = c.tmpFmt
		TimeDelta, _ := rc.ReadUintBE(3)
		c.Length, _ = rc.ReadUintBE(3)
		c.TypeID, _ = rc.ReadUintBE(1)
		if TimeDelta == 0xffffff {
			TimeDelta, _ = rc.ReadUintBE(4)
			c.exted = true
		} else {
			c.exted = false
		}
		c.TimeDelta = TimeDelta
		c.Timestamp += TimeDelta
		c.Done = false
		c.index = 0
		c.remain = c.Length
		c.Data = make([]byte, c.Length)
	case 2:
		c.Fmt = c.tmpFmt
		TimeDelta, _ := rc.ReadUintBE(3)
		if TimeDelta == 0xffffff {
			TimeDelta, _ = rc.ReadUintBE(4)
			c.exted = true
		} else {
			c.exted = false
		}
		c.TimeDelta = TimeDelta
		c.Timestamp += TimeDelta
		c.Done = false
		c.index = 0
		c.remain = c.Length
		c.Data = make([]byte, c.Length)
	case 3:
		if c.remain == 0 {
			// 新的chunk数据
			c.Timestamp += c.TimeDelta
			c.Done = false
			c.index = 0
			c.remain = c.Length
			c.Data = make([]byte, c.Length)
		} else {
			// 继续接收 上个chunk数据
		}
	default:
		return fmt.Errorf("invalid fmt=%d", c.Fmt)
	}

	size := int(c.remain)
	if size > int(rc.ChunkSize) {
		size = int(rc.ChunkSize)
	}

	buf := c.Data[c.index : c.index+uint32(size)]
	//n, err := rc.rw.Read(buf)
	_, err := io.ReadAtLeast(rc.rw, buf, len(buf))
	if err != nil {
		return err
	}
	//rc.log.Printf("total len: %d,  data len: %d", c.Length, n)
	c.index += uint32(size)
	c.remain -= uint32(size)
	if c.remain == 0 {
		c.Done = true
	}

	rc.log.Printf("Fmt: %d, CSID: %d, Timestamp: %d, Length: %d, TypeID: %d, StreamID: %d, TimeDelta: %d, exted: %t, index: %d, remain: %d, Done: %t, tmpFmt: %d",
		c.Fmt, c.CSID, c.Timestamp, c.Length, c.TypeID, c.StreamID, c.TimeDelta, c.exted, c.index, c.remain, c.Done, c.tmpFmt)
	return nil
}

func (rc *RtmpConn) ReadUintBE(n int) (uint32, error) {
	ret := uint32(0)
	for i := 0; i < n; i++ {
		b, err := rc.rw.ReadByte()
		if err != nil {
			rc.log.Println(err)
			return 0, err
		}
		ret = ret<<8 + uint32(b)
	}
	return ret, nil
}

func (rc *RtmpConn) ReadUintLE(n int) (uint32, error) {
	ret := uint32(0)
	for i := 0; i < n; i++ {
		b, err := rc.rw.ReadByte()
		if err != nil {
			rc.log.Println(err)
			return 0, err
		}
		ret += uint32(b) << uint32(i*8)
	}
	return ret, nil
}

type Chunk struct {
	Fmt       uint32
	CSID      uint32
	Timestamp uint32
	Length    uint32
	TypeID    uint32
	StreamID  uint32
	TimeDelta uint32
	exted     bool
	index     uint32
	remain    uint32
	Done      bool
	tmpFmt    uint32
	Data      []byte
}

func (rc *RtmpConn) ChunkMessageHandle(c *Chunk) {
	switch c.TypeID {
	case MsgIdSetChunkSize:
		rc.RemoteChunkSize = binary.BigEndian.Uint32(c.Data)
		rc.log.Println("set RemoteChunkSize =", rc.RemoteChunkSize)
	case MsgIdWindowAckSize:
		rc.RemoteWindowAckSize = binary.BigEndian.Uint32(c.Data)
		rc.log.Println("set RemoteWindowAckSize =", rc.RemoteWindowAckSize)
	case 17, 18, 20:
		rc.ChunkCmdMessageHandle(c)
	default:
		// c.TypeID = 4, MsgIdUserControlMessages, 可以完全忽略, ???
		rc.log.Println("undefined TypeID", c.TypeID)
	}
}

const (
	AMF0 = 0x00
	AMF3 = 0x03
)

const (
	AMF0_NUMBER_MARKER         = 0x00
	AMF0_BOOLEAN_MARKER        = 0x01
	AMF0_STRING_MARKER         = 0x02
	AMF0_OBJECT_MARKER         = 0x03
	AMF0_MOVIECLIP_MARKER      = 0x04
	AMF0_NULL_MARKER           = 0x05
	AMF0_UNDEFINED_MARKER      = 0x06
	AMF0_REFERENCE_MARKER      = 0x07
	AMF0_ECMA_ARRAY_MARKER     = 0x08 // MixedArray
	AMF0_OBJECT_END_MARKER     = 0x09
	AMF0_STRICT_ARRAY_MARKER   = 0x0a
	AMF0_DATE_MARKER           = 0x0b
	AMF0_LONG_STRING_MARKER    = 0x0c
	AMF0_UNSUPPORTED_MARKER    = 0x0d
	AMF0_RECORDSET_MARKER      = 0x0e
	AMF0_XML_DOCUMENT_MARKER   = 0x0f
	AMF0_TYPED_OBJECT_MARKER   = 0x10
	AMF0_ACMPLUS_OBJECT_MARKER = 0x11
)

const (
	AMF0_BOOLEAN_FALSE = 0x00
	AMF0_BOOLEAN_TRUE  = 0x01
	AMF0_STRING_MAX    = 65535
	AMF3_INTEGER_MAX   = 536870911
)

func AmfUnmarshal(r io.Reader) ([]interface{}, error) {
	var items []interface{}
	//for i := 0; i < 5; i++
	for {
		item, err := AmfDecode(r)
		if err != nil {
			return items, err
		}
		items = append(items, item)
	}
	return items, nil
}

func AmfDecode(r io.Reader) (interface{}, error) {
	// ??? 这里只能使用r.Read(), 不能使用r.ReadByte()
	marker := make([]byte, 1)
	_, err := r.Read(marker)
	if err != nil {
		return nil, err
	}
	//rc.log.Println("amf marker --->", marker[0])

	switch marker[0] {
	case AMF0_NUMBER_MARKER:
		return AmfDecodeNumber(r)
	case AMF0_STRING_MARKER:
		return AmfDecodeString(r)
	case AMF0_OBJECT_MARKER:
		return AmfDecodeObject(r)
	case AMF0_NULL_MARKER:
		return AmfDecodeNull(r)
	case AMF0_UNDEFINED_MARKER:
		return AmfDecodeNull(r)
	case AMF0_ECMA_ARRAY_MARKER:
		return AmfDecodeEcmaArray(r)
	case AMF0_BOOLEAN_MARKER:
		return AmfDecodeBoolean(r)
	}
	return nil, fmt.Errorf("invalid amf0 type %d", marker[0])
}

func AmfDecodeBoolean(r io.Reader) (bool, error) {
	var n uint8
	err := binary.Read(r, binary.BigEndian, &n)
	if err != nil {
		//rc.log.Println(err)
		return false, err
	}
	//rc.log.Println(n)
	if n != 0 {
		return true, nil
	}
	return false, nil
}

func AmfDecodeNull(r io.Reader) (interface{}, error) {
	/*
		b := make([]byte, 1)
		n, err := r.Read(b)
		if err != nil {
			rc.log.Println(err)
			return b, err
		}
		rc.log.Println(n, b)
	*/
	return nil, nil
}

func AmfDecodeEcmaArray(r io.Reader) (map[string]interface{}, error) {
	var num uint32
	err := binary.Read(r, binary.BigEndian, &num)
	if err != nil {
		//rc.log.Println(err)
		return nil, err
	}
	//rc.log.Println(num)

	obj := make(map[string]interface{})
	//rc.log.Println("amf EcmaArray start")
	for {
		key, err := AmfDecodeString(r)
		if err != nil {
			//rc.log.Println(err)
			return nil, err
		}

		if key == "" {
			b := make([]byte, 1)
			_, err := r.Read(b)
			if err != nil {
				//rc.log.Println(err)
				return nil, err
			}
			//rc.log.Println(n, b)
			//rc.log.Println("amf EcmaArray end")
			break
		}

		value, err := AmfDecode(r)
		if err != nil {
			//rc.log.Println(err)
			return nil, err
		}

		obj[key] = value
	}
	return obj, nil
}

func AmfDecodeObject(r io.Reader) (map[string]interface{}, error) {
	obj := make(map[string]interface{})
	//rc.log.Println("amf object start")
	for {
		key, err := AmfDecodeString(r)
		if err != nil {
			//rc.log.Println(err)
			return nil, err
		}

		if key == "" {
			b := make([]byte, 1)
			_, err := r.Read(b)
			if err != nil {
				//rc.log.Println(err)
				return nil, err
			}
			//rc.log.Println(n, b)
			//rc.log.Println("amf object end")
			break
		}

		value, err := AmfDecode(r)
		if err != nil {
			//rc.log.Println(err)
			return nil, err
		}

		obj[key] = value
	}
	return obj, nil
}

func AmfDecodeNumber(r io.Reader) (float64, error) {
	var n float64
	err := binary.Read(r, binary.BigEndian, &n)
	if err != nil {
		//rc.log.Println(err)
		return 0, err
	}
	//rc.log.Println(n)
	return n, nil
}

func AmfDecodeString(r io.Reader) (string, error) {
	var len uint16
	err := binary.Read(r, binary.BigEndian, &len)
	if err != nil {
		//rc.log.Println(err)
		return "", err
	}

	b := make([]byte, len)
	_, err = r.Read(b)
	if err != nil {
		//rc.log.Println(err)
		return "", err
	}
	//rc.log.Println(len, n, string(b))
	return string(b), nil
}

var (
	cmdConnect       = "connect"
	cmdFcpublish     = "FCPublish"
	cmdReleaseStream = "releaseStream"
	cmdCreateStream  = "createStream"
	cmdPublish       = "publish"
	cmdFCUnpublish   = "FCUnpublish"
	cmdDeleteStream  = "deleteStream"
	cmdPlay          = "play"
)

func (rc *RtmpConn) ChunkCmdMessageHandle(c *Chunk) error {
	if c.TypeID == 17 {
		c.Data = c.Data[1:]
	}
	r := bytes.NewReader(c.Data)
	items, err := AmfUnmarshal(r)
	if err != nil && err != io.EOF {
		rc.log.Println(err)
		return err
	}
	//rc.log.Println(len(items))

	v, ok := items[0].(string)
	if !ok {
		return fmt.Errorf("invalid cmd message")
	}
	rc.log.Println(v)

	switch v {
	case cmdConnect:
		if err = rc.RtmpCmdConnect(items[1:]); err != nil {
			rc.log.Println(err)
			return err
		}
		if err = rc.RtmpCmdConnectResp(c); err != nil {
			rc.log.Println(err)
			return err
		}
	case cmdFcpublish:
	case cmdReleaseStream:
	case cmdCreateStream:
		if err = rc.RtmpCmdCreateStream(items[1:]); err != nil {
			rc.log.Println(err)
			return err
		}
		if err = rc.RtmpCmdCreateStreamResp(c); err != nil {
			rc.log.Println(err)
			return err
		}
	case cmdPublish:
		if err = rc.RtmpCmdPublish(items[1:]); err != nil {
			rc.log.Println(err)
			return err
		}
		if err = rc.RtmpCmdPublishResp(c); err != nil {
			rc.log.Println(err)
			return err
		}
		rc.Done = true
		rc.isPublisher = true
		//rc.log.Println("handle publish request done")
	case cmdFCUnpublish:
	case cmdDeleteStream:
	case cmdPlay:
		if err = rc.RtmpCmdPlay(items[1:]); err != nil {
			rc.log.Println(err)
			return err
		}
		if err = rc.RtmpCmdPlayResp(c); err != nil {
			rc.log.Println(err)
			return err
		}
		rc.Done = true
		rc.isPublisher = false
		//rc.log.Println("handle play request done")
	default:
		rc.log.Printf("undefined cmd message\n%#v\n", items)
	}
	return nil
}

func (rc *RtmpConn) RtmpCmdPlay(items []interface{}) error {
	for k, item := range items {
		//rc.log.Println(k, item)
		switch item.(type) {
		case string:
			if k == 2 {
				rc.PublishInfo.Name = item.(string)
			} else if k == 3 {
				rc.PublishInfo.Type = item.(string)
			}
		case float64:
			rc.transactionID = int(item.(float64))
		case map[string]interface{}:
		}
	}
	return nil
}

const (
	streamBegin      uint32 = 0
	streamEOF        uint32 = 1
	streamDry        uint32 = 2
	setBufferLen     uint32 = 3
	streamIsRecorded uint32 = 4
	pingRequest      uint32 = 6
	pingResponse     uint32 = 7
)

/*
   +------------------------------+-------------------------
   |     Event Type ( 2- bytes )  | Event Data
   +------------------------------+-------------------------
   Pay load for the ‘User Control Message’.
*/
func NewChunkUCM(eType, Len uint32) Chunk {
	Len += 2
	c := Chunk{
		Fmt:      0,
		CSID:     2,
		TypeID:   4,
		StreamID: 1,
		Length:   Len,
		Data:     make([]byte, Len),
	}
	c.Data[0] = byte(eType >> 8 & 0xff)
	c.Data[1] = byte(eType & 0xff)
	for i := 0; i < 4; i++ {
		c.Data[2+i] = byte(1 >> uint32((3-i)*8) & 0xff)
	}
	return c
}

func (rc *RtmpConn) EventSend(c *Chunk, msg []byte) error {
	cc := Chunk{
		Fmt:       0,
		CSID:      c.CSID,
		Timestamp: 0,
		TypeID:    20,
		StreamID:  c.StreamID,
		Length:    uint32(len(msg)),
		Data:      msg,
	}
	rc.ChunkSplitSend(&cc)
	return nil
}

func (rc *RtmpConn) RtmpCmdPlayResp(c *Chunk) error {
	cc := NewChunkUCM(streamIsRecorded, 4)
	//rc.log.Println(cc)
	rc.ChunkSplitSend(&cc)
	cc = NewChunkUCM(streamBegin, 4)
	//rc.log.Println(cc)
	rc.ChunkSplitSend(&cc)

	event := make(map[string]interface{})
	event["level"] = "status"
	event["code"] = "NetStream.Play.Reset"
	event["description"] = "Playing and resetting stream."
	msg, err := AmfMarshal("onStatus", 0, nil, event)
	if err != nil {
		rc.log.Println(err)
		return err
	}
	rc.EventSend(c, msg)

	event["level"] = "status"
	event["code"] = "NetStream.Play.Start"
	event["description"] = "Started playing stream."
	msg, err = AmfMarshal("onStatus", 0, nil, event)
	if err != nil {
		rc.log.Println(err)
		return err
	}
	rc.EventSend(c, msg)

	event["level"] = "status"
	event["code"] = "NetStream.Data.Start"
	event["description"] = "Started playing stream."
	msg, err = AmfMarshal("onStatus", 0, nil, event)
	if err != nil {
		rc.log.Println(err)
		return err
	}
	rc.EventSend(c, msg)

	event["level"] = "status"
	event["code"] = "NetStream.Play.PublishNotify"
	event["description"] = "Started playing notify."
	msg, err = AmfMarshal("onStatus", 0, nil, event)
	if err != nil {
		rc.log.Println(err)
		return err
	}
	rc.EventSend(c, msg)
	return nil
}

func NewChunk(TypeID, Len, Data uint32) Chunk {
	c := Chunk{
		Fmt:      0,
		CSID:     2,
		TypeID:   TypeID,
		StreamID: 0,
		Length:   Len,
		Data:     make([]byte, Len),
	}
	is.PutU32BE(c.Data[:Len], Data)
	return c
}

func (rc *RtmpConn) WriteUintBE(v uint32, n int) error {
	for i := 0; i < n; i++ {
		b := byte(v>>uint32((n-i-1)<<3)) & 0xff
		//rc.log.Println(b)
		if err := rc.rw.WriteByte(b); err != nil {
			rc.log.Println(err)
			return err
		}
	}
	return nil
}

func (rc *RtmpConn) WriteUintLE(v uint32, n int) error {
	for i := 0; i < n; i++ {
		b := byte(v) & 0xff
		if err := rc.rw.WriteByte(b); err != nil {
			rc.log.Println(err)
			return err
		}
		v = v >> 8
	}
	return nil
}

func (rc *RtmpConn) ChunkSendHeader(c *Chunk) error {
	h := c.Fmt << 6
	switch {
	case c.CSID < 64:
		h |= c.CSID
		rc.WriteUintBE(h, 1)
	case c.CSID-64 < 256:
		h |= 0
		rc.WriteUintBE(h, 1)
		rc.WriteUintLE(c.CSID-64, 1)
	case c.CSID-64 < 65536:
		h |= 1
		rc.WriteUintBE(h, 1)
		rc.WriteUintLE(c.CSID-64, 2)
	}
	//rc.log.Println("chunk fmt, csid, 111 --->", c.Fmt, c.CSID, h)

	if c.Fmt == 3 {
		goto End
	}
	if c.Timestamp >= 0xffffff {
		rc.WriteUintBE(0xffffff, 3)
	} else {
		rc.WriteUintBE(c.Timestamp, 3)
	}
	if c.Fmt == 2 {
		goto End
	}
	if c.Length > 0xffffff {
		return fmt.Errorf("c.Lenth > 0xffffff")
	}
	rc.WriteUintBE(c.Length, 3)
	rc.WriteUintBE(c.TypeID, 1)
	if c.Fmt == 1 {
		goto End
	}
	rc.WriteUintBE(c.StreamID, 4)
End:
	if c.Timestamp >= 0xffffff {
		rc.WriteUintBE(c.Timestamp, 4)
	}
	return nil
}

func (rc *RtmpConn) ChunkSplitSend(c *Chunk) error {
	if c.TypeID == MsgIdSetChunkSize {
		rc.ChunkSize = binary.BigEndian.Uint32(c.Data)
	}

	switch c.TypeID {
	case TagScriptDataAmf0, TagScriptDataAmf3:
		c.CSID = 4
	case TagAudio:
		c.CSID = 4
	case TagVideo:
		c.CSID = 6
	}

	n := c.Length / rc.ChunkSize
	rc.log.Printf("send chunk, Lenght:%d, ChunkSize:%d, ChunkNum:%d",
		c.Length, rc.ChunkSize, n+1)
	for i := uint32(0); i <= n; i++ {
		if i == 0 {
			c.Fmt = uint32(0)
		} else {
			c.Fmt = uint32(3)
		}
		rc.log.Printf("send chunk ---> %d, Fmt: %d, CSID: %d, Timestamp: %d, Length: %d, TypeID: %d, StreamID: %d, index: %d, remain: %d, tmpFmt: %d",
			i, c.Fmt, c.CSID, c.Timestamp, c.Length, c.TypeID, c.StreamID, c.index, c.remain, c.tmpFmt)

		rc.ChunkSendHeader(c)
		// chunk send data
		s := i * rc.ChunkSize
		e := s + rc.ChunkSize
		if uint32(len(c.Data))-s <= rc.ChunkSize {
			e = s + uint32(len(c.Data)) - s
		}
		//rc.log.Println(s, e)
		buf := c.Data[s:e]
		if _, err := rc.rw.Write(buf); err != nil {
			rc.log.Println(err)
			return err
		}
		rc.rw.Flush()
	}
	return nil
}

// marshal unmarshal
func AmfMarshal(args ...interface{}) ([]byte, error) {
	buff := bytes.NewBuffer(nil)
	for _, v := range args {
		_, err := AmfEncode(buff, v)
		if err != nil {
			//rc.log.Println(err)
			return nil, err
		}
	}
	msg := buff.Bytes()
	//rc.log.Println(msg)
	return msg, nil
}

func AmfEncode(w io.Writer, val interface{}) (int, error) {
	if val == nil {
		return AmfEncodeNull(w)
	}
	v := reflect.ValueOf(val)
	if !v.IsValid() {
		return AmfEncodeNull(w)
	}

	switch v.Kind() {
	case reflect.String:
		s := v.String()
		//rc.log.Println(len(s), s)
		if len(s) <= AMF0_STRING_MAX {
			return AmfEncodeString(w, s, true)
		} else {
			//return AmfEncodeLongString(w, s, true)
		}
	case reflect.Bool:
		return AmfEncodeBool(w, v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return AmfEncodeNumber(w, float64(v.Int()))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return AmfEncodeNumber(w, float64(v.Uint()))
	case reflect.Float32, reflect.Float64:
		return AmfEncodeNumber(w, float64(v.Float()))
	case reflect.Array, reflect.Slice:
		len := v.Len()
		arr := make([]interface{}, len)
		for i := 0; i < len; i++ {
			arr[i] = v.Index(int(i)).Interface() // ???
		}
		return AmfEncodeStrictArray(w, arr)
	case reflect.Map:
		obj, ok := val.(map[string]interface{})
		if !ok {
			return 0, fmt.Errorf("not map[string]interface{}")
		}
		return AmfEncodeMap(w, obj)
	}
	return 0, nil
}

func AmfEncodeStrictArray(w io.Writer, val []interface{}) (int, error) {
	n := 0
	_, err := AmfEncodeWriteMarker(w, AMF0_STRICT_ARRAY_MARKER)
	if err != nil {
		//rc.log.Println(err)
		return 0, err
	}
	n += 1

	err = binary.Write(w, binary.BigEndian, uint32(len(val)))
	if err != nil {
		//rc.log.Println(err)
		return 0, err
	}
	n += 4

	for _, v := range val {
		m, err := AmfEncode(w, v)
		if err != nil {
			//rc.log.Println(err)
			return 0, err
		}
		n += m
	}
	return n, nil
}

func AmfEncodeMap(w io.Writer, val map[string]interface{}) (int, error) {
	n := 0
	_, err := AmfEncodeWriteMarker(w, AMF0_OBJECT_MARKER)
	if err != nil {
		//rc.log.Println(err)
		return 0, err
	}
	n += 1

	var m int
	for k, v := range val {
		m, err = AmfEncodeString(w, k, false)
		if err != nil {
			//rc.log.Println(err)
			return 0, err
		}
		n += m

		m, err = AmfEncode(w, v)
		if err != nil {
			//rc.log.Println(err)
			return 0, err
		}
		n += m
	}

	m, err = AmfEncodeString(w, "", false)
	if err != nil {
		//rc.log.Println(err)
		return 0, err
	}
	n += m

	_, err = AmfEncodeWriteMarker(w, AMF0_OBJECT_END_MARKER)
	if err != nil {
		//rc.log.Println(err)
		return n, err
	}
	n += 1
	return n, nil
}

func AmfEncodeBool(w io.Writer, val bool) (int, error) {
	n := 0
	_, err := AmfEncodeWriteMarker(w, AMF0_BOOLEAN_MARKER)
	if err != nil {
		//rc.log.Println(err)
		return 0, err
	}
	n += 1

	b := make([]byte, 1)
	if val {
		b[0] = AMF0_BOOLEAN_TRUE
	} else {
		b[0] = AMF0_BOOLEAN_FALSE
	}

	m, err := w.Write(b)
	if err != nil {
		//rc.log.Println(err)
		return 0, err
	}
	n += m
	return n, nil
}

func AmfEncodeNumber(w io.Writer, val float64) (int, error) {
	n := 0
	_, err := AmfEncodeWriteMarker(w, AMF0_NUMBER_MARKER)
	if err != nil {
		//rc.log.Println(err)
		return 0, err
	}
	n += 1

	err = binary.Write(w, binary.BigEndian, &val)
	if err != nil {
		//rc.log.Println(err)
		return 0, err
	}
	n += 8
	return n, err
}

func AmfEncodeString(w io.Writer, val string, marker bool) (int, error) {
	n := 0
	if marker {
		_, err := AmfEncodeWriteMarker(w, AMF0_STRING_MARKER)
		if err != nil {
			//rc.log.Println(err)
			return 0, err
		}
		n += 1
	}

	err := binary.Write(w, binary.BigEndian, uint16(len(val)))
	if err != nil {
		//rc.log.Println(err)
		return 0, err
	}

	m, err := w.Write([]byte(val))
	if err != nil {
		//rc.log.Println(err)
		return 0, err
	}
	n += m
	return n, nil
}

func AmfEncodeNull(w io.Writer) (int, error) {
	_, err := AmfEncodeWriteMarker(w, AMF0_NULL_MARKER)
	if err != nil {
		//rc.log.Println(err)
		return 0, err
	}
	return 1, nil
}

func AmfEncodeWriteMarker(w io.Writer, m byte) (int, error) {
	b := make([]byte, 1)
	b[0] = m
	return w.Write(b)
}

func (rc *RtmpConn) RtmpCmdConnectResp(c *Chunk) error {
	cc := NewChunk(MsgIdWindowAckSize, 4, 2500000)
	//rc.log.Println(cc)
	rc.ChunkSplitSend(&cc)
	cc = NewChunk(MsgIdSetPeerBandwidth, 5, 2500000)
	cc.Data[4] = 2 // ???
	//rc.log.Println(cc)
	rc.ChunkSplitSend(&cc)
	cc = NewChunk(MsgIdSetChunkSize, 4, 1024)
	//rc.log.Println(cc)
	rc.ChunkSplitSend(&cc)

	resp := make(map[string]interface{})
	resp["fmsVer"] = "FMS/3,0,1,123"
	resp["capabilities"] = 31

	event := make(map[string]interface{})
	event["level"] = "status"
	event["code"] = "NetConnection.Connect.Success"
	event["description"] = "Connection succeeded."
	event["objectEncoding"] = rc.ConnInfo.ObjectEncoding

	msg, err := AmfMarshal("_result", rc.transactionID, resp, event)
	if err != nil {
		rc.log.Println(err)
		return err
	}
	cc = Chunk{
		Fmt:       0,
		CSID:      c.CSID,
		Timestamp: 0,
		TypeID:    20,
		StreamID:  c.StreamID,
		Length:    uint32(len(msg)),
		Data:      msg,
	}
	rc.ChunkSplitSend(&cc)
	return nil
}

func (rc *RtmpConn) RtmpCmdConnect(items []interface{}) error {
	for _, item := range items {
		switch item.(type) {
		case float64:
			id := int(item.(float64))
			if id != 1 { //???
				return fmt.Errorf("invalid transactionID %d", id)
			}
			rc.transactionID = id // ???
		case map[string]interface{}:
			obj := item.(map[string]interface{})
			if v, ok := obj["app"]; ok {
				rc.ConnInfo.App = v.(string)
			}
			if v, ok := obj["flashVer"]; ok {
				rc.ConnInfo.Flashver = v.(string)
			}
			if v, ok := obj["tcUrl"]; ok {
				rc.ConnInfo.TcUrl = v.(string)
			}
			if v, ok := obj["objectEncoding"]; ok {
				rc.ConnInfo.ObjectEncoding = int(v.(float64))
			}
		}
	}
	rc.log.Printf("tranID:%d, %#v", rc.transactionID, rc.ConnInfo)
	return nil
}

func (rc *RtmpConn) RtmpCmdCreateStreamResp(c *Chunk) error {
	msg, err := AmfMarshal("_result", rc.transactionID, nil, rc.streamID)
	if err != nil {
		rc.log.Println(err)
		return err
	}
	cc := Chunk{
		Fmt:       0,
		CSID:      c.CSID,
		Timestamp: 0,
		TypeID:    20,
		StreamID:  c.StreamID,
		Length:    uint32(len(msg)),
		Data:      msg,
	}
	rc.ChunkSplitSend(&cc)
	return nil
}

func (rc *RtmpConn) RtmpCmdCreateStream(items []interface{}) error {
	for _, item := range items {
		switch item.(type) {
		case string:
		case float64:
			rc.transactionID = int(item.(float64))
		case map[string]interface{}:
		}
	}
	rc.log.Println(rc.transactionID, rc.ConnInfo)
	return nil
}

func (rc *RtmpConn) RtmpCmdPublishResp(c *Chunk) error {
	event := make(map[string]interface{})
	event["level"] = "status"
	event["code"] = "NetStream.Publish.Start"
	event["description"] = "Start publising."

	msg, err := AmfMarshal("onStatus", 0, nil, event)
	if err != nil {
		rc.log.Println(err)
		return err
	}
	cc := Chunk{
		Fmt:       0,
		CSID:      c.CSID,
		Timestamp: 0,
		TypeID:    20,
		StreamID:  c.StreamID,
		Length:    uint32(len(msg)),
		Data:      msg,
	}
	rc.ChunkSplitSend(&cc)
	return nil
}

func (rc *RtmpConn) RtmpCmdPublish(items []interface{}) error {
	for k, item := range items {
		//rc.log.Println(k, item)
		switch item.(type) {
		case string:
			if k == 2 {
				rc.PublishInfo.Name = item.(string)
			} else if k == 3 {
				rc.PublishInfo.Type = item.(string)
			}
		case float64:
			rc.transactionID = int(item.(float64))
		case map[string]interface{}:
		}
	}
	return nil
}

// 1 接收&拼接chunk数据; 2 处理chunk数据;
func (rc *RtmpConn) ChunkHandle(cp *Chunk) error {
	i := 0
	for {
		bh, err := rc.ReadUintBE(1)
		if err != nil {
			rc.log.Println(err)
			return err
		}

		fmt := bh >> 6
		csid := bh & 0x3f
		rc.log.Printf("chunk ---> %d, fmt:%d, csid:%d", i, fmt, csid)
		i++

		c, ok := rc.Chunks[csid]
		if !ok {
			c = Chunk{}
		}
		c.tmpFmt = fmt
		c.CSID = csid

		err = rc.ChunkMerge(&c)
		if err != nil {
			rc.log.Println(err)
			return err
		}
		rc.Chunks[csid] = c
		if c.Done {
			//rc.log.Println(c.Data)
			*cp = c
			break
		}
	}
	rc.ChunkMessageHandle(cp)

	rc.Received += uint32(cp.Length)
	rc.AckReceived += uint32(cp.Length)
	if rc.Received >= 0xf0000000 {
		rc.Received = 0
	}
	if rc.AckReceived >= rc.RemoteWindowAckSize { // ???
		rc.log.Println("send RemoteWindowAckSize,", rc.AckReceived, rc.RemoteWindowAckSize)
		// 1 创建chunk数据;
		c := Chunk{Fmt: 0, CSID: 2, TypeID: MsgIdAck, StreamID: 0, Length: 4, Data: make([]byte, 4)}
		is.PutU32BE(c.Data[:4], rc.AckReceived)
		// 2 拆分chunk; 3 序列化chunk; 2 发送chunk;
		rc.ChunkSplitSend(&c)
		rc.AckReceived = 0
	}
	return nil
}

// 控制消息: 分为 块流控制消息 和 用户控制消息
// message type id = 1, 块流控制消息, 设置块大小, 默认的块大小为128 byte, 最大16777215(0xFFFFFF)
// message type id = 2, 终止消息
// message type id = 3, 块流控制消息, 确认
// message type id = 4, 用户控制消息
// message type id = 5, 块流控制消息, 窗口大小
// message type id = 6, 块流控制消息, 设置对端带宽
const (
	_ = iota
	MsgIdSetChunkSize
	MsgIdAbortMessage
	MsgIdAck
	MsgIdUserControlMessages
	MsgIdWindowAckSize
	MsgIdSetPeerBandwidth
)

func (rc *RtmpConn) HandlerNegotiation() error {
	var c Chunk
	i := 0
	//for i := 0; i < 6; i++
	for {
		rc.log.Println("negotiation ----->", i)
		i++
		if err := rc.ChunkHandle(&c); err != nil {
			rc.log.Println(err)
			return err
		}
		rc.log.Println("rc.Done", rc.Done)
		if rc.Done {
			break
		}
	}
	return nil
}

// ip:port.log
// ip:port.log
// cctv1_publisher_ip:port.log
// cctv1_player_ip:port.log
type RtmpConn struct {
	logName string
	log     *log.Logger
	Key     string
	URL     string
	UID     string
	start   bool

	net.Conn
	ChunkSize           uint32
	RemoteChunkSize     uint32
	WindowAckSize       uint32
	RemoteWindowAckSize uint32
	rw                  *bufio.ReadWriter
	Chunks              map[uint32]Chunk
	Received            uint32
	AckReceived         uint32
	Done                bool
	streamID            int
	isPublisher         bool
	transactionID       int
	ConnInfo            ConnectInfo
	PublishInfo         PublishInfo
	//decoder       *amf.Decoder
	//encoder       *amf.Encoder
	//bytesw        *bytes.Buffer
	//rw                  *ReadWriter
	//pool                *pool.Pool
	//chunks              map[uint32]c
}

func RtmpHandler(rc *RtmpConn) {
	err := rc.HandshakeServer()
	if err != nil {
		rc.log.Println(err)
		return
	}
	rc.log.Println("RtmpHandshakeServer ok")

	err = rc.HandlerNegotiation()
	if err != nil {
		rc.log.Println(err)
		return
	}
	rc.log.Println("RtmpHandlerNegotiation ok")

	/*
		rc.URL = rc.ConnInfo.TcUrl + "/" + rc.PublishInfo.Name
		Url, err := url.Parse(rc.URL)
		if err != nil {
			rc.log.Println(err)
			return
		}
		rc.log.Printf("%#v\n", Url)
		rc.Key = strings.TrimLeft(Url.Path, "/")
		rc.log.Println(rc.URL, rc.Key, rc.isPublisher)
	*/
	rc.Key = fmt.Sprintf("%s/%s", rc.ConnInfo.App, rc.PublishInfo.Name)
	rc.log.Printf("app:%s stream:%s key:%s isPublisher:%v url:%s",
		rc.ConnInfo.App, rc.PublishInfo.Name, rc.Key, rc.isPublisher,
		rc.ConnInfo.TcUrl+"/"+rc.PublishInfo.Name)

	if rc.isPublisher {
		f1 := strings.ReplaceAll(rc.Key, "/", "_")
		f2 := rc.logName
		rc.logName = fmt.Sprintf("%s_%s_%s", f1, "publisher", f2)
		os.Rename(f2, rc.logName)
		rc.log.Println("new publisher")
		log.Println("new publisher", rc.logName)

		// 要想重新推流，只能先断流然后再推
		s := &Stream{Cache{nil, nil, nil, make([]*Packet, 0), 0}, rc,
			make(map[string]*RtmpConn)}
		livego.Streams[rc.Key] = s
		rc.log.Printf("%#v", s.Publisher)

		go s.Start()
	} else {
		f1 := strings.ReplaceAll(rc.Key, "/", "_")
		f2 := rc.logName
		rc.logName = fmt.Sprintf("%s_%s_%s", f1, "player", f2)
		os.Rename(f2, rc.logName)
		rc.log.Println("new player")
		log.Println("new player", rc.logName)

		s, ok := livego.Streams[rc.Key]
		//rc.log.Println(s, ok)
		if !ok {
			rc.log.Printf("have not stream %s publisher", rc.Key)
			return
		}
		rc.Key = fmt.Sprintf("%s/%s", rc.Key, rc.RemoteAddr().String())
		s.Players[rc.Key] = rc
	}
}

type Stream struct {
	Cache
	Publisher *RtmpConn
	Players   map[string]*RtmpConn
}

const (
	pTypeMetadata = iota
	pTypeAvcSeqHeader
	pTypeAacSeqHeader
	pTypeVideo
	pTypeAudio
)

type AVTag struct {
	soundFormat     uint8
	soundRate       uint8
	soundSize       uint8
	soundType       uint8
	aacPacketType   uint8
	frameType       uint8
	codecID         uint8
	avcPacketType   uint8
	compositionTime int32
}

type Packet struct {
	pType     uint32
	TimeStamp uint32 // dts
	StreamID  uint32
	Data      []byte
	AVTag
}

const (
	TagAudio          = 8
	TagVideo          = 9
	TagScriptDataAmf0 = 18
	TagScriptDataAmf3 = 0xf
)

func (s *Stream) Start() {
	rc := s.Publisher
	var p Packet
	//for i := 0; i < 6; i++ {
	i := 0
	for {
		rc.log.Printf("recv packet ---> %d", i)
		i++

		err := s.Recv(&p)
		if err != nil {
			rc.log.Println(err)
			return
		}

		s.CachePacket(p)

		rc.log.Println("players num", len(s.Players))
		for k, player := range s.Players {
			rc.log.Println(k, player.start)
			if !player.start { // 发送缓存数据
				if err := s.CacheSend(player); err != nil {
					rc.log.Println("stream CacheSend() fail,", k)
					delete(s.Players, k)
				}
				player.start = true
			} else { // 发送实时数据
				if err := s.Send(player, &p); err != nil {
					rc.log.Println("stream Send() fail,", k)
					delete(s.Players, k)
				}
			}
		}
	}
}

func (s *Stream) CacheSend(rc *RtmpConn) error {
	rc.log.Println("CacheSend begin")
	if err := s.Send(rc, s.Cache.Metadata); err != nil {
		return err
	}
	if err := s.Send(rc, s.Cache.AvcSeqHeader); err != nil {
		return err
	}
	if err := s.Send(rc, s.Cache.AacSeqHeader); err != nil {
		return err
	}
	for i := uint32(0); i < s.Cache.GopNum; i++ {
		if err := s.Send(rc, s.Cache.Gop[i]); err != nil {
			return err
		}
	}
	rc.log.Println("CacheSend end")
	return nil
}

// s.Send() s.Recv() 为逆操作
func (s *Stream) Send(rc *RtmpConn, p *Packet) error {
	// 1 packet 转为 chunk; 2 切片chunk, 然后发送;
	var c Chunk
	c.Data = p.Data
	c.Length = uint32(len(p.Data))
	c.StreamID = p.StreamID
	c.Timestamp = p.TimeStamp

	switch p.pType {
	case pTypeMetadata:
		c.TypeID = TagScriptDataAmf0
	case pTypeAvcSeqHeader:
		c.TypeID = TagVideo
	case pTypeAacSeqHeader:
		c.TypeID = TagAudio
	case pTypeVideo:
		c.TypeID = TagVideo
	case pTypeAudio:
		c.TypeID = TagAudio
	}

	rc.log.Printf("Fmt: %d, CSID: %d, Timestamp: %d, Length: %d, TypeID: %d, StreamID: %d, TimeDelta: %d, exted: %t, index: %d, remain: %d, Done: %t, tmpFmt: %d",
		c.Fmt, c.CSID, c.Timestamp, c.Length, c.TypeID, c.StreamID, c.TimeDelta, c.exted, c.index, c.remain, c.Done, c.tmpFmt)

	if err := rc.ChunkSplitSend(&c); err != nil {
		rc.log.Println(err)
		return err
	}
	return nil
}

type Cache struct {
	Metadata     *Packet
	AvcSeqHeader *Packet
	AacSeqHeader *Packet
	Gop          []*Packet
	GopNum       uint32
}

func (s *Stream) CachePacket(p Packet) {
	switch p.pType {
	case pTypeMetadata:
		s.Metadata = &p
	case pTypeAvcSeqHeader:
		s.AvcSeqHeader = &p
	case pTypeAacSeqHeader:
		s.AacSeqHeader = &p
	case pTypeVideo, pTypeAudio:
		s.CacheGop(&p)
	}
}

func (s *Stream) CacheGop(p *Packet) {
	// 遇到 视频关键帧 且 非AVC sequence header
	if p.pType == pTypeVideo && p.frameType == 1 {
		s.Gop = s.Gop[:0]
		s.GopNum = 0
	}
	s.Gop = append(s.Gop, p)
	s.GopNum++
	//rc.log.Println(s.GopNum)
}

func (s *Stream) Recv(p *Packet) error {
	// 1 接收并合并chunk; 2 chunk 转为 packet;
	rc := s.Publisher // *RtmpConn
	var c Chunk
	for {
		if err := rc.ChunkHandle(&c); err != nil {
			//rc.log.Println(err)
			return err
		}
		if c.TypeID == TagAudio || c.TypeID == TagVideo ||
			c.TypeID == TagScriptDataAmf0 ||
			c.TypeID == TagScriptDataAmf3 {
			break
		}
	}
	data := c.Data
	c.Data = nil
	//rc.log.Printf("chunk: %#v, len=%d", c, len(data))
	c.Data = data
	//rc.log.Println(c.Data)

	p.Data = c.Data
	p.StreamID = c.StreamID
	p.TimeStamp = c.Timestamp

	switch c.TypeID {
	case TagScriptDataAmf0, TagScriptDataAmf3:
		p.pType = pTypeMetadata
	case TagAudio:
		p.pType = pTypeAudio
		tf, err := ParseAudioTag(p)
		if err != nil {
			//rc.log.Println(err)
			return err
		}
		if tf {
			p.pType = pTypeAacSeqHeader
		}
	case TagVideo:
		p.pType = pTypeVideo
		tf, err := ParseVideoTag(p)
		if err != nil {
			//rc.log.Println(err)
			return err
		}
		if tf {
			p.pType = pTypeAvcSeqHeader
		}
	}

	p.Data = nil
	//rc.log.Printf("%#v, len=%d", p, len(c.Data))
	p.Data = c.Data
	//rc.log.Println(p.Data)
	return nil
}

func ParseAudioTag(p *Packet) (bool, error) {
	if len(p.Data) < 1 {
		return false, fmt.Errorf("audio data len < 1")
	}
	tag := p.Data[0]
	p.soundFormat = tag >> 4
	p.soundRate = (tag >> 2) & 0x3
	p.soundSize = (tag >> 1) & 0x1
	p.soundType = tag & 0x1
	if p.soundFormat == 10 {
		p.aacPacketType = p.Data[1]
	}
	if p.aacPacketType == 0 {
		return true, nil
	}
	return false, nil
}

func ParseVideoTag(p *Packet) (bool, error) {
	if len(p.Data) < 5 {
		return false, fmt.Errorf("video data len < 5")
	}
	tag := p.Data[0]
	p.frameType = tag >> 4
	p.codecID = tag & 0xf
	if p.frameType == 1 || p.frameType == 2 {
		p.avcPacketType = p.Data[1]
		for i := 2; i < 5; i++ { // ???
			p.compositionTime = p.compositionTime<<8 + int32(p.Data[i])
		}
	}
	if p.avcPacketType == 0 {
		return true, nil
	}
	return false, nil
}

func NewRW(conn net.Conn) *bufio.ReadWriter {
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	return bufio.NewReadWriter(r, w)
}

type ConnectInfo struct {
	App            string `amf:"app" json:"app"`
	Flashver       string `amf:"flashVer" json:"flashVer"`
	SwfUrl         string `amf:"swfUrl" json:"swfUrl"`
	TcUrl          string `amf:"tcUrl" json:"tcUrl"`
	Fpad           bool   `amf:"fpad" json:"fpad"`
	AudioCodecs    int    `amf:"audioCodecs" json:"audioCodecs"`
	VideoCodecs    int    `amf:"videoCodecs" json:"videoCodecs"`
	VideoFunction  int    `amf:"videoFunction" json:"videoFunction"`
	PageUrl        string `amf:"pageUrl" json:"pageUrl"`
	ObjectEncoding int    `amf:"objectEncoding" json:"objectEncoding"`
}

type PublishInfo struct {
	Name string
	Type string
}

func RtmpServer() {
	l, err := net.Listen("tcp", "127.0.0.1:1935")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("rtmp server listen on :1935")

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}

		rc := &RtmpConn{}
		rc.Conn = conn
		rc.ChunkSize = 128
		rc.RemoteChunkSize = 128
		rc.WindowAckSize = 2500000
		rc.RemoteWindowAckSize = 2500000
		rc.rw = NewRW(conn)
		rc.Chunks = make(map[uint32]Chunk)
		rc.Received = 0
		rc.AckReceived = 0
		rc.Done = false
		rc.streamID = 1

		fn := fmt.Sprintf("%s.log", rc.RemoteAddr().String())
		rc.logName = strings.ReplaceAll(fn, ":", "_")
		fp, err := os.OpenFile(rc.logName, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Println(err)
			return
		}
		rc.log = log.New(fp, "", log.LstdFlags|log.Lshortfile)
		rc.log.Println("new rtmp conn:", rc.RemoteAddr().String())

		log.Println("new rtmp conn:", rc.logName)
		//log.Println("local rc:", rc.LocalAddr().String())
		go RtmpHandler(rc)
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	go HttpServer()
	RtmpServer()
}
