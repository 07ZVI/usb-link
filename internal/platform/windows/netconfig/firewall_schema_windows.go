//go:build windows && amd64

package netconfig

import (
	"context"
	"errors"
	"strings"
	"suhang/usbnet/internal/platform/windows/wincom"
)

type NativeFirewallPropertySchema struct {
	Name  string `json:"name"`
	Type  int32  `json:"cim_type"`
	Array bool   `json:"array"`
}
type NativeFirewallClassSchema struct {
	Name       string                         `json:"class"`
	Properties []NativeFirewallPropertySchema `json:"properties,omitempty"`
	Methods    []NativeFirewallMethodSchema   `json:"methods,omitempty"`
	Error      string                         `json:"error,omitempty"`
}

type NativeFirewallMethodSchema struct {
	Name  string                         `json:"name"`
	In    []NativeFirewallPropertySchema `json:"in,omitempty"`
	Out   []NativeFirewallPropertySchema `json:"out,omitempty"`
	Error string                         `json:"error,omitempty"`
}

// NativeFirewallSchemaSnapshot queries fixed local class definitions only.
// No instance selectors, rule contents, user values, credentials or mutation
// enter this diagnostic. Schema observations never authorize firewall changes.
func NativeFirewallSchemaSnapshot(ctx context.Context) []NativeFirewallClassSchema {
	classes := []string{"MSFT_NetFirewallRule"}
	for _, g := range firewallGroups {
		if g.class != "" {
			classes = append(classes, g.class)
		}
	}
	return nativeFixedClassSchemaSnapshot(ctx, classes)
}

// Fixed metadata only: no instance values or caller-selected class/query.
func NativeInterfaceConfigurationSchemaSnapshot(ctx context.Context) []NativeFirewallClassSchema {
	return nativeFixedClassSchemaSnapshot(ctx, []string{"MSFT_NetIPAddress", "MSFT_NetIPInterface"})
}

func nativeFixedClassSchemaSnapshot(ctx context.Context, classes []string) []NativeFirewallClassSchema {
	out := []NativeFirewallClassSchema{}
	err := withFirewall(ctx, func(svc *wincom.Dispatch) error {
		for _, name := range classes {
			item := NativeFirewallClassSchema{Name: name}
			class, e := comObject(svc.Call("Get", wincom.String(name)))
			if e != nil {
				item.Error = "CLASS_UNAVAILABLE"
				out = append(out, item)
				continue
			}
			props, e := comObject(class.Get("Properties_"))
			if e != nil {
				class.Close()
				item.Error = "PROPERTIES_UNAVAILABLE"
				out = append(out, item)
				continue
			}
			e = enumerateCOM(props, 128, func(p *wincom.Dispatch) error {
				name, e := comString(p, "Name")
				if e != nil || name == "" || len(name) > 128 || strings.ContainsAny(name, "\r\n\x00") {
					return errors.New("SCHEMA_NAME_INVALID")
				}
				typ, e := comInt(p, "CIMType")
				if e != nil {
					return e
				}
				v, e := p.Get("IsArray")
				defer v.Clear()
				if e != nil {
					return e
				}
				array, e := v.Bool()
				if e != nil {
					return e
				}
				item.Properties = append(item.Properties, NativeFirewallPropertySchema{name, typ, array})
				return nil
			})
			props.Close()
			if e == nil {
				item.Methods, e = readFirewallMethods(class)
			}
			class.Close()
			if e != nil {
				item.Properties = nil
				item.Error = "SCHEMA_INCOMPLETE"
			}
			out = append(out, item)
		}
		return nil
	})
	if err != nil {
		return []NativeFirewallClassSchema{{Error: "LOCAL_PROVIDER_UNAVAILABLE"}}
	}
	return out
}

func validateFirewallProperty(d *wincom.Dispatch, name string, types []int32, array bool) error {
	props, e := comObject(d.Get("Properties_"))
	if e != nil {
		return e
	}
	defer props.Close()
	property, e := comObject(props.Call("Item", wincom.String(name)))
	if e != nil {
		return errors.New("USB_NATIVE_FIREWALL_PROPERTY_UNSUPPORTED")
	}
	defer property.Close()
	typ, e := comInt(property, "CIMType")
	if e != nil {
		return errors.New("USB_NATIVE_FIREWALL_PROPERTY_UNSUPPORTED")
	}
	ok := false
	for _, allowed := range types {
		ok = ok || typ == allowed
	}
	if !ok {
		return errors.New("USB_NATIVE_FIREWALL_PROPERTY_TYPE_UNSUPPORTED")
	}
	v, e := property.Get("IsArray")
	defer v.Clear()
	if e != nil {
		return e
	}
	got, e := v.Bool()
	if e != nil || got != array {
		return errors.New("USB_NATIVE_FIREWALL_PROPERTY_ARRAY_UNSUPPORTED")
	}
	return nil
}
func nativeFirewallCreationPreflight(svc *wincom.Dispatch) error {
	class, e := comObject(svc.Call("Get", wincom.String("MSFT_NetFirewallRule")))
	if e != nil {
		return e
	}
	defer class.Close()
	for _, name := range []string{"InstanceID", "ElementName", "RuleGroup", "Description"} {
		if e = validateFirewallProperty(class, name, []int32{8}, false); e != nil {
			return e
		}
	}
	for _, name := range []string{"Enabled", "Action", "Direction", "Profiles", "EdgeTraversalPolicy"} {
		if e = validateFirewallProperty(class, name, []int32{18, 19}, false); e != nil {
			return e
		}
	}
	for _, name := range []string{"LooseSourceMapping", "LocalOnlyMapping"} {
		if e = validateFirewallProperty(class, name, []int32{11}, false); e != nil {
			return e
		}
	}
	for _, g := range firewallGroups {
		if g.class == "" {
			continue
		}
		d, e := comObject(svc.Call("Get", wincom.String(g.class)))
		if e != nil {
			return errors.New("USB_NATIVE_FIREWALL_FILTER_CLASS_UNSUPPORTED")
		}
		for _, name := range g.fields {
			types, array := []int32{8}, false
			switch name {
			case "LocalAddress", "RemoteAddress", "LocalPort", "RemotePort", "IcmpType", "InterfaceAlias":
				array = true
			case "DynamicTransport", "InterfaceType", "Authentication", "Encryption":
				types = []int32{18, 19}
			case "OverrideBlockRules":
				types = []int32{11}
			}
			if e = validateFirewallProperty(d, name, types, array); e != nil {
				d.Close()
				return e
			}
		}
		d.Close()
		if e != nil {
			return e
		}
	}
	return nil
}

func readFirewallMethodParams(v wincom.Value) ([]NativeFirewallPropertySchema, error) {
	if v.IsNull() || v.IsEmpty() {
		return nil, nil
	}
	d, e := v.Dispatch()
	if e != nil {
		return nil, e
	}
	defer d.Close()
	props, e := comObject(d.Get("Properties_"))
	if e != nil {
		return nil, e
	}
	defer props.Close()
	result := []NativeFirewallPropertySchema{}
	e = enumerateCOM(props, 64, func(p *wincom.Dispatch) error {
		name, e := comString(p, "Name")
		if e != nil || name == "" || len(name) > 128 || strings.ContainsAny(name, "\r\n\x00") {
			return errors.New("SCHEMA_NAME_INVALID")
		}
		typ, e := comInt(p, "CIMType")
		if e != nil {
			return e
		}
		a, e := p.Get("IsArray")
		defer a.Clear()
		if e != nil {
			return e
		}
		array, e := a.Bool()
		if e != nil {
			return e
		}
		result = append(result, NativeFirewallPropertySchema{name, typ, array})
		return nil
	})
	return result, e
}
func readFirewallMethods(class *wincom.Dispatch) ([]NativeFirewallMethodSchema, error) {
	methods, e := comObject(class.Get("Methods_"))
	if e != nil {
		return nil, e
	}
	defer methods.Close()
	result := []NativeFirewallMethodSchema{}
	e = enumerateCOM(methods, 64, func(method *wincom.Dispatch) error {
		name, e := comString(method, "Name")
		if e != nil || name == "" || len(name) > 128 || strings.ContainsAny(name, "\r\n\x00") {
			return errors.New("SCHEMA_NAME_INVALID")
		}
		item := NativeFirewallMethodSchema{Name: name}
		in, e := method.Get("InParameters")
		if e == nil {
			item.In, e = readFirewallMethodParams(in)
		}
		in.Clear()
		if e == nil {
			out, oe := method.Get("OutParameters")
			if oe == nil {
				item.Out, oe = readFirewallMethodParams(out)
			}
			out.Clear()
			e = oe
		}
		if e != nil {
			item.In = nil
			item.Out = nil
			item.Error = "METHOD_PARAMETERS_UNSUPPORTED"
		}
		result = append(result, item)
		return nil
	})
	return result, e
}
