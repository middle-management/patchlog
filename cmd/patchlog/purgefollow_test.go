package main

import (
	"testing"
	"time"
)

func TestFollowPurgesArgs(t *testing.T) {
	a := followPurgesArgs{
		FollowPurgesFrom:     []string{"https://staging.example", "http://localhost:9080"},
		FollowPurgesImporter: []string{"https://staging.example=user:importer", "https://staging.example=svc:sync", "http://localhost:9080=user:importer"},
		FollowPurgesBearer:   []string{"https://staging.example=tok"},
		FollowPurgesURL:      []string{"https://staging.example=http://staging:8080"},
		FollowPurgesInterval: time.Minute,
	}
	o, err := a.options("https://cms.example")
	if err != nil {
		t.Fatal(err)
	}
	if p := o.Origins["https://staging.example"]; p.Bearer != "tok" || p.BaseURL != "http://staging:8080" || o.Interval != time.Minute ||
		len(p.Importers) != 2 || p.Importers[0] != "user:importer" || p.Importers[1] != "svc:sync" {
		t.Fatalf("%+v", o)
	}
	if _, ok := o.Origins["http://localhost:9080"]; !ok || len(o.Origins) != 2 {
		t.Fatalf("%+v", o.Origins)
	}
	if o, err := (followPurgesArgs{}).options("https://cms.example"); err != nil || o.Origins != nil || o.Interval != -1 {
		t.Fatalf("none: %+v %v", o, err)
	}
	for _, bad := range []followPurgesArgs{
		{FollowPurgesFrom: []string{"https://Staging.example"}},
		{FollowPurgesFrom: []string{"https://staging.example/"}},
		{FollowPurgesFrom: []string{"https://staging.example:443"}},
		{FollowPurgesFrom: []string{"https://cms.example"}},
		{FollowPurgesFrom: []string{"https://staging.example"}, FollowPurgesBearer: []string{"https://other.example=tok"}},
		{FollowPurgesFrom: []string{"https://staging.example"}, FollowPurgesURL: []string{"https://staging.example"}},
		// v0.88 §G.1: an origin needs the principals that import from it.
		{FollowPurgesFrom: []string{"https://staging.example"}},
		{FollowPurgesFrom: []string{"https://staging.example"}, FollowPurgesImporter: []string{"https://other.example=user:x"}},
		{FollowPurgesFrom: []string{"https://staging.example"}, FollowPurgesImporter: []string{"https://staging.example="}},
	} {
		if _, err := bad.options("https://cms.example"); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}
