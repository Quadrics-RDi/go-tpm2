package internal

import "fmt"

type Wbuf struct {
	b []byte
}

func (w *Wbuf) U8(v uint8) {
	w.b = append(w.b, byte(v))
}

func (w *Wbuf) U16(v uint16) {
	w.b = append(w.b, byte(v>>8), byte(v))
}

func (w *Wbuf) U32(v uint32) {
	w.b = append(w.b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func (w *Wbuf) Bytes(p []byte) {
	w.b = append(w.b, p...)
}

func (w *Wbuf) Get() []byte {
	return w.b
}

func (w *Wbuf) Tpmb2(p []byte) {
	w.U16(uint16(len(p)))
	w.Bytes(p)
}

func (w *Wbuf) String() {
	fmt.Printf("buffer bytes: %x\n", w.b)
}
