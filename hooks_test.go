package ztchooks

import (
	"testing"
	"time"
)

var networkJoin []byte = []byte(`{"org_id": "1bb4dc96-f311-4c4a-ac93-551cbc0fa3da", "hook_id": "ae76d4c0-c94e-4025-a648-2c504eb90e3c", "hook_type": "NETWORK_JOIN", "member_id": "a02505e545", "network_id": "19d9808567057972"}`)
var netConfigChanged []byte = []byte(`{"org_id": "1bb4dc96-f311-4c4a-ac93-551cbc0fa3da", "hook_id": "ae76d4c0-c94e-4025-a648-2c504eb90e3c", "user_id": "5fb96260-df39-4f18-b0ad-f37930ec613d", "hook_type": "NETWORK_CONFIG_CHANGED", "network_id": "19d9808567a2c324", "new_config": {"id": "19d9808567a2c324", "dns": {"domain": "", "servers": null}, "mtu": 2800, "name": "hook test 01", "nwid": "19d9808567a2c324", "tags": [], "rules": [{"or": false, "not": true, "type": "MATCH_ETHERTYPE", "etherType": 2048}, {"or": false, "not": true, "type": "MATCH_ETHERTYPE", "etherType": 2054}, {"or": false, "not": true, "type": "MATCH_ETHERTYPE", "etherType": 34525}, {"type": "ACTION_DROP"}, {"type": "ACTION_ACCEPT"}], "issuer": "", "routes": [{"target": "10.144.0.0/16"}], "objtype": "network", "private": true, "clientId": "", "provider": "", "revision": 4, "authTokens": null, "ssoEnabled": false, "fromCentral": true, "capabilities": [], "creationTime": 1691521314163, "v4AssignMode": {"zt": true}, "v6AssignMode": {"zt": false, "6plane": false, "rfc4193": false}, "multicastLimit": 32, "enableBroadcast": true, "remoteTraceLevel": 0, "ipAssignmentPools": [{"ipRangeEnd": "10.144.255.254", "ipRangeStart": "10.144.0.1"}], "remoteTraceTarget": null, "authorizationEndpoint": ""}, "old_config": {"id": "19d9808567a2c324", "dns": {"domain": "", "servers": null}, "mtu": 2800, "name": "hook test 01", "nwid": "19d9808567a2c324", "tags": [], "rules": [{"or": false, "not": true, "type": "MATCH_ETHERTYPE", "etherType": 2048}, {"or": false, "not": true, "type": "MATCH_ETHERTYPE", "etherType": 2054}, {"or": false, "not": true, "type": "MATCH_ETHERTYPE", "etherType": 34525}, {"type": "ACTION_DROP"}, {"type": "ACTION_ACCEPT"}], "issuer": "", "routes": [{"target": "10.144.0.0/16"}], "objtype": "network", "private": true, "clientId": "", "provider": "", "revision": 3, "authTokens": null, "ssoEnabled": false, "fromCentral": true, "capabilities": [], "creationTime": 1691521314163, "v4AssignMode": {"zt": true}, "v6AssignMode": {"zt": false, "6plane": false, "rfc4193": false}, "multicastLimit": 32, "enableBroadcast": true, "remoteTraceLevel": 0, "ipAssignmentPools": [{"ipRangeEnd": "10.144.255.254", "ipRangeStart": "10.144.0.1"}], "remoteTraceTarget": null, "authorizationEndpoint": ""}, "user_email": "glimberg@gmail.com"}`)

func TestGetHookType(t *testing.T) {
	hType, err := GetHookType(networkJoin)
	if err != nil {
		t.Fatal("error decoding hook type")
	}
	if hType != NETWORK_JOIN {
		t.Fatalf("decoded incorrect type.  Expected NETWORK_JOIN, got %s", hType)
	}

	hType, err = GetHookType(netConfigChanged)
	if err != nil {
		t.Fatal("error decoding hook type")
	}
	if hType != NETWORK_CONFIG_CHANGED {
		t.Fatalf("decoded incorrect type. Expected NETWORK_CONFIG_CHANGE, got %s", hType)
	}
}

func TestVerifySignature(t *testing.T) {
	psk := "778c6dab5feca625c7831644d18c4d0e4b3a337bff8a1e1c8f938f9cc20e6536"
	signature := "t=1694033429,v1=04d87956d1953f28ac04d441f139fc655109e9b5c64396fb55dbdf567c735f86"
	payload := []byte("{\"hook_id\":\"ae76d4c0-c94e-4025-a648-2c504eb90e3c\",\"org_id\":\"1bb4dc96-f311-4c4a-ac93-551cbc0fa3da\",\"hook_type\":\"NETWORK_JOIN\",\"network_id\":\"19d9808567a17ccf\",\"member_id\":\"a02505e545\"}")

	err := VerifyHookSignature(psk, signature, payload, 65535*time.Hour)
	if err != nil {
		t.Errorf("error verifying hook signature: %s", err.Error())
	}
}
