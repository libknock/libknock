package codec

import "encoding/binary"

type BinaryReader struct {
	buf []byte
	pos int
	err error
}

func NewReader(buf []byte, invalid error) *BinaryReader { return &BinaryReader{buf: buf, err: invalid} }
func (r *BinaryReader) Pos() int                        { return r.pos }
func (r *BinaryReader) Remaining() int                  { return len(r.buf) - r.pos }
func (r *BinaryReader) ReadByte() (byte, error) {
	if r.Remaining() < 1 {
		return 0, r.err
	}
	b := r.buf[r.pos]
	r.pos++
	return b, nil
}
func (r *BinaryReader) ReadUint16() (uint16, error) {
	if r.Remaining() < 2 {
		return 0, r.err
	}
	v := binary.BigEndian.Uint16(r.buf[r.pos : r.pos+2])
	r.pos += 2
	return v, nil
}
func (r *BinaryReader) ReadUint64() (uint64, error) {
	if r.Remaining() < 8 {
		return 0, r.err
	}
	v := binary.BigEndian.Uint64(r.buf[r.pos : r.pos+8])
	r.pos += 8
	return v, nil
}
func (r *BinaryReader) ReadFixed(n int) ([]byte, error) {
	if n < 0 || r.Remaining() < n {
		return nil, r.err
	}
	v := r.buf[r.pos : r.pos+n]
	r.pos += n
	return v, nil
}
func (r *BinaryReader) ReadVarBytes(n int, copyOut bool) ([]byte, error) {
	v, err := r.ReadFixed(n)
	if err != nil || !copyOut {
		return v, err
	}
	return append([]byte(nil), v...), nil
}

type BinaryWriter struct{ buf []byte }

func NewWriter(capacity int) *BinaryWriter { return &BinaryWriter{buf: make([]byte, 0, capacity)} }
func (w *BinaryWriter) Bytes() []byte      { return w.buf }
func (w *BinaryWriter) PutByte(v byte)     { w.buf = append(w.buf, v) }
func (w *BinaryWriter) WriteUint16(v uint16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	w.buf = append(w.buf, b[:]...)
}
func (w *BinaryWriter) WriteUint64(v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	w.buf = append(w.buf, b[:]...)
}
func (w *BinaryWriter) WriteFixed(v []byte) { w.buf = append(w.buf, v...) }
func (w *BinaryWriter) WriteVarBytes(v []byte, prefixBytes int) {
	if prefixBytes == 1 {
		w.PutByte(byte(len(v)))
	} else if prefixBytes == 2 {
		w.WriteUint16(uint16(len(v)))
	}
	w.WriteFixed(v)
}

type TLV struct {
	Type  uint16
	Value []byte
}

func EncodeTLVs(tlvs []TLV, frameTooLarge error) ([]byte, error) {
	var total int
	for _, tlv := range tlvs {
		if len(tlv.Value) > 65535 {
			return nil, frameTooLarge
		}
		total += 4 + len(tlv.Value)
		if total > 65535 {
			return nil, frameTooLarge
		}
	}
	w := NewWriter(total)
	for _, tlv := range tlvs {
		w.WriteUint16(tlv.Type)
		w.WriteVarBytes(tlv.Value, 2)
	}
	return w.Bytes(), nil
}

func DecodeTLVs(raw []byte, invalid error) ([]TLV, error) {
	r := NewReader(raw, invalid)
	out := make([]TLV, 0)
	for r.Remaining() > 0 {
		typ, err := r.ReadUint16()
		if err != nil {
			return nil, err
		}
		n, err := r.ReadUint16()
		if err != nil {
			return nil, err
		}
		v, err := r.ReadVarBytes(int(n), true)
		if err != nil {
			return nil, err
		}
		out = append(out, TLV{Type: typ, Value: v})
	}
	return out, nil
}
