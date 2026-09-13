package checkers

import (
	"net/netip"
	"testing"

	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/config"
	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/inetlookup"
	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/subnetfilter"
	"go4.org/netipx"
)

type emptyInetLookup struct{}

func (emptyInetLookup) Cidrs(inetlookup.CidrsOpt) *netipx.IPSet {
	var b netipx.IPSetBuilder
	set, _ := b.IPSet()
	return set
}

func (emptyInetLookup) Asns(inetlookup.AsnsOpt) []int32 { return nil }

func (emptyInetLookup) OrgTerms(inetlookup.OrgTermsOpt) []string { return nil }

func (emptyInetLookup) IpInfo(ip netip.Addr) inetlookup.IpInfo {
	return inetlookup.IpInfo{Ip: ip}
}

func TestGetSubnetfilterItemsUsesHostDefaults(t *testing.T) {
	sf := subnetfilter.New(emptyInetLookup{})
	targets := []config.WebhostTarget{{Name: "test", Filter: `host("example.com")`}}

	items, err := getSubnetfilterItems(sf, targets)
	if err != nil {
		t.Fatalf("getSubnetfilterItems: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1", len(items))
	}

	bag := items[0].Bag
	if bag.Name != "test" || bag.Count != 1 || bag.Port != 443 || bag.Sni != "example.com" || bag.Host != "example.com" {
		t.Fatalf("unexpected bag: %+v", bag)
	}
}

func TestGetSubnetfilterItemsAppliesOverrides(t *testing.T) {
	sf := subnetfilter.New(emptyInetLookup{})
	targets := []config.WebhostTarget{{
		Name:           "test",
		Filter:         `host("example.com")`,
		Count:          3,
		Port:           8443,
		Sni:            "custom.example",
		Host:           "host.example",
		Tcp1620skip:    true,
		RandomHostname: true,
	}}

	items, err := getSubnetfilterItems(sf, targets)
	if err != nil {
		t.Fatalf("getSubnetfilterItems: %v", err)
	}
	bag := items[0].Bag
	want := WebhostGochanBag{
		Name:           "test",
		Count:          3,
		Port:           8443,
		Sni:            "custom.example",
		Host:           "host.example",
		Tcp1620skip:    true,
		RandomHostname: true,
	}
	if bag != want {
		t.Fatalf("got %+v, want %+v", bag, want)
	}
}

func TestGetSubnetfilterItemsRejectsInvalidFilter(t *testing.T) {
	sf := subnetfilter.New(emptyInetLookup{})
	_, err := getSubnetfilterItems(sf, []config.WebhostTarget{{Name: "test", Filter: `host("example.com"`}})
	if err == nil {
		t.Fatal("expected invalid filter to fail")
	}
}
