package ddb

// Gestures (§7.2, §7.4). GET /ns/{ns}/gestures/{gesture} lists a
// namespace's revisions and tombstones written with a gesture or undoing
// it, in the order they were written. A revision records its gesture
// and undoes (REV items), and each also gets a marker in the namespace's
// partition, GEST#<gesture>#<name>#<pos12>#<created13>, carrying the
// position of its item in the commit. Markers are written just before
// the commit, outside its transaction (a batch's steps would outgrow the
// 100 actions), like schema references' (schemas.go); one whose commit
// then failed, or was checked again at another time, names a revision
// that isn't the one at its position, and GestureRevs leaves it out.
//
// The order a write commits in is its entry's position, known only at
// commit, so a listing reads every marker of the gesture and orders the
// revisions they confirm by the entry that wrote them, then the item and
// step within it — as SQL's revision seqs order them. Gestures are a
// user's few saves; a page costs the whole gesture's markers.

import (
	"context"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// GestureMark is a revision listed under a gesture: name's revision at
// Pos, of id RevID, written at Created as its commit's Item-th item.
type GestureMark struct {
	Gesture string
	Created int64
	Item    int
	Pos     uint64
	Name    string
	RevID   string
}

func keyGesture(ns string, m GestureMark) Key {
	return Key{nsPK(ns), fmt.Sprintf("GEST#%s#%s#%s#%013d", m.Gesture, m.Name, padPos(m.Pos), m.Created)}
}

// GestureMarks lists the markers of c's steps: one under each step's
// gesture, one under what it undoes.
func GestureMarks(c *Commit) []GestureMark {
	var out []GestureMark
	for i, it := range c.Items {
		for j, st := range it.Steps {
			m := GestureMark{Created: c.Created, Item: i, Pos: it.HeadPos + uint64(j) + 1, Name: it.Name, RevID: st.ID}
			if st.Gesture != "" {
				m.Gesture = st.Gesture
				out = append(out, m)
			}
			if st.Undoes != "" && st.Undoes != st.Gesture {
				m.Gesture = st.Undoes
				out = append(out, m)
			}
		}
	}
	return out
}

// PutGestureMarks writes markers in ns, before the commit of their
// revisions.
func (s *Store) PutGestureMarks(ctx context.Context, ns string, ms []GestureMark) error {
	for _, m := range ms {
		_, err := s.Client.PutItem(ctx, &dynamodb.PutItemInput{
			TableName: &s.Table,
			Item: withKey(keyGesture(ns, m), item{
				"name": avS(m.Name), "pos": avN(m.Pos), "revId": avS(m.RevID), "created": avI(m.Created), "item": avN(uint64(m.Item)),
			}),
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// GestureRev is a revision a marker confirmed, with its place in the
// commit that wrote it.
type GestureRev struct {
	Name string
	Item int
	Rev  *RevInfo
}

// GestureRevs lists ns's revisions written with gesture or undoing it,
// in the order they were written: by the entry that wrote them, then
// their item and step in it.
func (s *Store) GestureRevs(ctx context.Context, ns, gesture string) ([]GestureRev, error) {
	var marks []item
	if err := s.eachItem(ctx, ns, "GEST#"+gesture+"#", func(i item) error {
		marks = append(marks, i)
		return nil
	}); err != nil {
		return nil, err
	}
	keys := make([]Key, len(marks))
	for i, m := range marks {
		keys[i] = keyRev(ns, m.s("name"), m.n("pos"))
	}
	revs, err := s.batchGet(ctx, keys)
	if err != nil {
		return nil, err
	}
	var out []GestureRev
	for i, m := range marks {
		it, ok := revs[keys[i]]
		if !ok {
			continue
		}
		ri := scanRevInfo(it)
		if ri.ID != m.s("revId") || ri.Created != int64(m.n("created")) || ri.Gesture != gesture && ri.Undoes != gesture {
			continue // a commit that didn't happen as marked
		}
		out = append(out, GestureRev{Name: m.s("name"), Item: int(m.n("item")), Rev: &ri})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].before(out[j]) })
	return out, nil
}

// before orders revisions as they were written.
func (g GestureRev) before(o GestureRev) bool {
	if g.Rev.LogPos != o.Rev.LogPos {
		return g.Rev.LogPos < o.Rev.LogPos
	}
	if g.Item != o.Item {
		return g.Item < o.Item
	}
	return g.Rev.Pos < o.Rev.Pos
}
