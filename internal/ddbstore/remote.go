package ddbstore

// Remote branches (§G.3), the source side: a namespace's registrations
// of branches living in other deployments. Each is a REG#<origin>#<name>
// item — the registration's at, its latest entry and the one before, and
// when it expires — written in the commit of its "branch" entry
// (Commit.Registration), conditioned on the latest entry the checks read,
// so two renewals can't both win.

import (
	"context"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func keyReg(ns, origin, name string) Key { return Key{nsPK(ns), "REG#" + origin + "#" + name} }

func (s *Store) registrationActs(c *Commit, entry logRow) []types.TransactWriteItem {
	r := c.Registration
	if r == nil {
		return nil
	}
	it := item{"origin": avS(r.Origin), "name": avS(r.Name), "atPos": avN(r.AtPos), "nsPos": avN(entry.pos), "expires": avI(r.Expires)}
	if r.PrevPos > 0 {
		it["prevPos"] = avN(r.PrevPos)
	}
	put := &types.Put{TableName: &s.Table, Item: withKey(keyReg(c.NS, r.Origin, r.Name), it)}
	if r.PrevPos == 0 {
		put.ConditionExpression = strptr("attribute_not_exists(PK)")
	} else {
		put.ConditionExpression = strptr("nsPos = :p")
		put.ExpressionAttributeValues = map[string]types.AttributeValue{":p": avN(r.PrevPos)}
	}
	return []types.TransactWriteItem{{Put: put}}
}

func scanRegistration(i item) *Registration {
	return &Registration{Origin: i.s("origin"), Name: i.s("name"), AtPos: i.n("atPos"), NSPos: i.n("nsPos"), PrevPos: i.n("prevPos"), Expires: int64(i.n("expires"))}
}

// RegistrationOf reads ns's registration of origin's name; nil for none.
func (s *Store) RegistrationOf(ctx context.Context, ns, origin, name string) (*Registration, error) {
	it, err := s.getItem(ctx, keyReg(ns, origin, name))
	if it == nil || err != nil {
		return nil, err
	}
	return scanRegistration(item(it)), nil
}

// Registrations lists ns's registrations unexpired at now (milliseconds),
// by origin, then name.
func (s *Store) Registrations(ctx context.Context, ns string, now int64) ([]*Registration, error) {
	var out []*Registration
	err := s.eachItem(ctx, ns, "REG#", func(i item) error {
		if r := scanRegistration(i); r.Expires > now {
			out = append(out, r)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out, err
}

func less(a, b *Registration) bool {
	if c := strings.Compare(a.Origin, b.Origin); c != 0 {
		return c < 0
	}
	return a.Name < b.Name
}
