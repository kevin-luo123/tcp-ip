package orderedmap

import (
	"errors"
	"time"
)

type (
	OrderedMap struct {
		acks  []uint32            // expected ack num
		data  map[uint32]([]byte) // seq to data
		times map[uint32](time.Time)
	}
)

func NewOrderedMap() *OrderedMap {
	return &OrderedMap{
		acks:  []uint32{},
		data:  make(map[uint32]([]byte)),
		times: make(map[uint32]time.Time),
	}
}

// Add or update an element
func (om *OrderedMap) Set(ack uint32, data []byte, time time.Time) {
	if _, exists := om.data[ack]; !exists {
		om.acks = append(om.acks, ack) // Add key to order list if new
	}
	om.data[ack] = data
	om.times[ack] = time
}

func (om *OrderedMap) Len() int {
	return len(om.acks)
}

// Get an element
func (om *OrderedMap) Get(ack uint32) ([]byte, bool) {
	value, exists := om.data[ack]
	return value, exists
}

func (om *OrderedMap) Pop() (uint32, []byte, error) { //returns seq, data, err
	if len(om.acks) == 0 {
		return 0, []byte{0}, errors.New("empty q")
	}
	ack := om.acks[0]
	om.acks = om.acks[1:]
	payload := om.data[ack]
	om.Delete(ack)
	return ack - uint32(len(payload)), payload, nil
}

func (om *OrderedMap) GetTime(ack uint32) (time.Time, bool) {
	value, exists := om.times[ack]
	return value, exists
}

// Remove an element
func (om *OrderedMap) Delete(ack uint32) {
	if _, exists := om.data[ack]; exists {
		delete(om.times, ack)
		delete(om.data, ack)
		for i, k := range om.acks {
			if k == ack {
				om.acks = append(om.acks[:i], om.acks[i+1:]...)
				break
			}
		}
	}
}

func (om *OrderedMap) DeleteUpTo(ackNum uint32) {
    for seqNum := range om.data {
        if int32(seqNum - ackNum) < 0 {
            delete(om.data, seqNum)
			delete(om.times, seqNum)
        }
    }
}
