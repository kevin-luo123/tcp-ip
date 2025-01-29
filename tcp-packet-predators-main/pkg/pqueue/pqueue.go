package pqueue

// Item is a structure to hold value and priority
type Packet struct {
	Start uint32
	End   uint32
}

type PriorityQueue []*Packet

func (pq PriorityQueue) Len() int { return len(pq) }

func (pq PriorityQueue) Less(i, j int) bool {
	// Lower priority value comes first
	return pq[i].Start < pq[j].Start
}

func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *PriorityQueue) Push(x interface{}) {
	item := x.(*Packet)
	*pq = append(*pq, item)
}

func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[:n-1]
	return item
}

func (pq *PriorityQueue) Look(idx int) *Packet {
	if pq.Len() == 0 {
		return nil // Return nil if the queue is empty
	}
	return (*pq)[idx] // The root element is always at index 0
}
