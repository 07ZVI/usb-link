//go:build windows && amd64

package netconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"suhang/usbnet/internal/platform/windows/wincom"
)

const shadowPolicyCLSID = "{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}"

var shadowMembers = []string{"Name", "Grouping", "Description", "ApplicationName", "ServiceName", "LocalAddresses", "RemoteAddresses", "LocalPorts", "RemotePorts", "Interfaces", "InterfaceTypes", "Protocol", "Profiles", "Direction", "Action", "Enabled", "EdgeTraversal", "EdgeTraversalOptions", "LocalAppPackageId", "LocalUserAuthorizedList", "LocalUserOwner", "RemoteMachineAuthorizedList", "RemoteUserAuthorizedList", "SecureFlags", "IcmpTypesAndCodes"}

func shadowHRESULT(e error) uint32 {
	var n interface{ NativeHRESULT() uint32 }
	if errors.As(e, &n) {
		return n.NativeHRESULT()
	}
	return 0
}
func shadowRead(ctx context.Context, d *wincom.Dispatch) (map[string]FirewallShadowField, error) {
	out := map[string]FirewallShadowField{}
	for _, member := range shadowMembers {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		f := FirewallShadowField{Name: member, Status: "unavailable"}
		v, e := d.Get(member)
		if e != nil {
			f.HRESULT = shadowHRESULT(e)
			f.Kind = "getter_error"
			v.Clear()
			out[member] = f
			continue
		}
		switch member {
		case "Interfaces":
			f.Kind = "string_array"
			f.Actual, e = v.Strings(8)
		case "Protocol", "Profiles", "Direction", "Action", "EdgeTraversalOptions", "SecureFlags":
			f.Kind = "integer"
			var i int32
			i, e = v.Int()
			if e == nil {
				f.Actual = []string{fmt.Sprint(i)}
			}
		case "Enabled", "EdgeTraversal":
			f.Kind = "boolean"
			var b bool
			b, e = v.Bool()
			if e == nil {
				f.Actual = []string{fmt.Sprint(b)}
			}
		default:
			f.Kind = "string"
			var t string
			t, e = v.String()
			if e == nil {
				f.Actual = []string{t}
			}
		}
		if v.IsNull() {
			f.Kind = "null"
			e = errors.New("SHADOW_NULL")
		}
		if v.IsEmpty() {
			f.Kind = "empty"
			e = errors.New("SHADOW_EMPTY")
		}
		v.Clear()
		if e == nil {
			for _, x := range f.Actual {
				if len(x) > 1024 {
					e = errors.New("SHADOW_BOUND")
				}
			}
		}
		if e == nil {
			f.Status = "observed"
		} else {
			f.Actual = nil
			f.HRESULT = shadowHRESULT(e)
			if f.Kind != "null" && f.Kind != "empty" {
				f.Kind = "type_unknown"
			}
		}
		out[member] = f
	}
	return out, nil
}
func observeFirewallShadow(ctx context.Context, s FirewallShadowScope, owner func() error) FirewallShadowSample {
	sample := FirewallShadowSample{Status: "unavailable"}
	if e := ctx.Err(); e != nil {
		return sample
	}
	if owner() != nil {
		return sample
	}
	alias, e := nativeRuleInterface(ctx, s.Proof)
	if e != nil {
		return sample
	}
	if (s.Role == "mac" || s.Role == "core_mac") && nativeMacScope(ctx, s.Proof) != nil {
		return sample
	}
	specs := shadowLegacySpecs(s, alias)
	if len(specs) == 0 {
		return sample
	}
	verify := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := owner(); e != nil {
			return e
		}
		now, e := nativeRuleInterface(ctx, s.Proof)
		if e != nil {
			return e
		}
		if now != alias {
			return errors.New("SHADOW_INTERFACE_CHANGED")
		}
		return nil
	}
	e = wincom.WithApartment(func() error {
		policy, e := wincom.Create(shadowPolicyCLSID)
		if e != nil {
			return e
		}
		defer policy.Close()
		rules, e := comObject(policy.Get("Rules"))
		if e != nil {
			return e
		}
		defer rules.Close()
		var count int32
		count, e = comInt(rules, "Count")
		if e != nil {
			return e
		}
		if count < 0 || count > 8192 {
			return errors.New("SHADOW_RULE_BOUND")
		}
		candidates := make([][]map[string]FirewallShadowField, len(specs))
		e = enumerateCOM(rules, 8192, func(d *wincom.Dispatch) error {
			if e := ctx.Err(); e != nil {
				return e
			}
			name, e := comString(d, "Name")
			if e != nil {
				return e
			}
			relevant := false
			for _, spec := range specs {
				if name == spec.display {
					relevant = true
					break
				}
			}
			if !relevant {
				return nil
			}
			first, e := shadowRead(ctx, d)
			if e != nil {
				return e
			}
			second, e := shadowRead(ctx, d)
			if e != nil {
				return e
			}
			if !reflect.DeepEqual(first, second) {
				return errors.New("SHADOW_RULE_CHANGED")
			}
			for i, spec := range specs {
				if name != spec.display {
					continue
				}
				if len(candidates[i]) >= 16 {
					return errors.New("SHADOW_CANDIDATE_BOUND")
				}
				candidates[i] = append(candidates[i], first)
			}
			return nil
		})
		if e != nil {
			return e
		}
		if e = verify(); e != nil {
			return e
		}
		sample.AllComparedAgree = true
		for i, spec := range specs {
			c := candidates[i]
			selected := c
			if len(c) > 1 {
				selected = nil
				for _, candidate := range c {
					matched := true
					for _, k := range []string{"Interfaces", "Protocol", "LocalAddresses", "RemoteAddresses", "LocalPorts", "RemotePorts"} {
						if _, applies := spec.fields[k]; applies && !shadowAnchorMatch(candidate, spec, k) {
							matched = false
						}
					}
					if matched {
						selected = append(selected, candidate)
					}
				}
			}
			r := FirewallShadowRule{Selector: i, CandidateCount: len(selected)}
			if len(selected) != 1 {
				sample.AllComparedAgree = false
				sample.Rules = append(sample.Rules, r)
				continue
			}
			keys := []string{}
			for k := range spec.fields {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				f := selected[0][k]
				f.Expected = append([]string(nil), spec.fields[k]...)
				if f.Status == "observed" {
					if shadowSame(k, f.Actual, f.Expected) {
						f.Status = "match"
					} else {
						f.Status = "mismatch"
					}
				}
				if f.Status != "match" {
					sample.AllComparedAgree = false
				}
				if shadowRedacted(k, s) {
					f.Actual = nil
					f.Expected = nil
					f.Redacted = true
				}
				r.Fields = append(r.Fields, f)
			}
			sample.Rules = append(sample.Rules, r)
		}
		if e = verify(); e != nil {
			return e
		}
		sample.Status = "observed"
		return nil
	})
	if e != nil {
		sample.Status = "unavailable"
		sample.AllComparedAgree = false
		sample.Rules = nil
		sample.HRESULT = shadowHRESULT(e)
	}
	// Marshal is an output bound, not an admission/permission check.
	if b, _ := json.Marshal(sample); len(b) > 65536 {
		sample.Rules = nil
		sample.Status = "unavailable"
		sample.AllComparedAgree = false
	}
	return sample
}
func shadowAnchorMatch(actual map[string]FirewallShadowField, spec shadowSpec, key string) bool {
	v, ok := actual[key]
	return ok && v.Status == "observed" && shadowSame(key, v.Actual, spec.fields[key])
}
