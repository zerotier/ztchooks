import { verifySignature } from "..";

const psk = "778c6dab5feca625c7831644d18c4d0e4b3a337bff8a1e1c8f938f9cc20e6536"
const signature = "t=1694033429,v1=04d87956d1953f28ac04d441f139fc655109e9b5c64396fb55dbdf567c735f86"
const payload = "{\"hook_id\":\"ae76d4c0-c94e-4025-a648-2c504eb90e3c\",\"org_id\":\"1bb4dc96-f311-4c4a-ac93-551cbc0fa3da\",\"hook_type\":\"NETWORK_JOIN\",\"network_id\":\"19d9808567a17ccf\",\"member_id\":\"a02505e545\"}";

describe('testing verifySignature', () => {
    test('test verify signature should pass', () => {
        expect(verifySignature(psk, signature, payload, Number.MAX_SAFE_INTEGER)).toBe(true);
    });
});
