package typeutil

import "sort"

type sortable[T any] struct {
	data        []T
	compareFunc func(a, b T) bool
}

func (s sortable[T]) Len() int {
	return len(s.data)
}

func (s sortable[T]) Swap(i, j int) {
	s.data[i], s.data[j] = s.data[j], s.data[i]
}

func (s sortable[T]) Less(i, j int) bool {
	return s.compareFunc(s.data[i], s.data[j])
}

// Sort sorts passed slice using provided comparator function.
//
// Comparator should return whether one element is less than another.
func Sort[T any](list []T, compareFunc func(a, b T) bool) {
	sorter := sortable[T]{
		data:        list,
		compareFunc: compareFunc,
	}

	sort.Sort(sorter)
}
