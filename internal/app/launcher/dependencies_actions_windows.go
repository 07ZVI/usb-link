//go:build windows && amd64
package launcher
import("encoding/json";"suhang/usbnet/internal/dependencies")
func extendDesktopSnapshot(display json.RawMessage) json.RawMessage {var d map[string]json.RawMessage;if json.Unmarshal(display,&d)!=nil{return display};d["dependencies"],_=json.Marshal(dependencies.Default.Snapshot());b,_:=json.Marshal(d);return b}
func dependencyAction(payload json.RawMessage)(bool,error){var r struct{Action string `json:"action"`};if json.Unmarshal(payload,&r)!=nil||r.Action!="dependency-refresh"{return false,nil};if e:=strictCorePayload(payload,&r);e!=nil{return true,e};dependencies.Default.Refresh();return true,nil}
