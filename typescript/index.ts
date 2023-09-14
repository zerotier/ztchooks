
import * as crypto from "crypto-js";

export function verifySignature(
    preSharedKey: string,
    sigHeader: string,
    payload: string,
    toleranceSeconds: number): boolean {

    try {
        var header = parseHeader(sigHeader, toleranceSeconds);
        var expectedSig = generateExpectedSignature(header, preSharedKey, payload);

        for (var i = 0; i < header.signatures.length; i++) {
            if (header.signatures[i] === expectedSig) {
                return true;
            }
        }
    } catch (error) {
        console.log(error)
        return false;
    }
    return false;
}

class signedHeader {
    timestamp: number;
    signatures: string[];

    constructor(ts = 0, sigs = []) {
        this.timestamp = ts;
        this.signatures = sigs;
    }
}

function parseHeader(sigHeader: string, toleranceSeconds: number): signedHeader {
    var pairs: string[] = sigHeader.split(',');
    var sh = decode(pairs, toleranceSeconds);
    if (sh.signatures.length == 0) {
        throw "Invalid Signature";
    }

    return sh
}

function decode(pairs: string[], toleranceSeconds: number): signedHeader {
    var sh = new signedHeader();
    for (var i = 0; i < pairs.length; i++) {
        var p = pairs[i];

        var parts = p.split('=');
        if (parts.length != 2) {
            throw "Invalid Header";
        }

        var item = parts[0];
        var value = parts[1];

        if (item == "t") {
            var timestamp = parseInt(value, 10);
            if (timestamp == undefined || isNaN(timestamp)) {
                throw "Invalid Header";
            }
            sh.timestamp = timestamp;
        }

        if (item[0] == "v") {
            sh.signatures.push(value)
        }
    }

    if ((Date.now() / 1000) > (sh.timestamp + toleranceSeconds)) {
        throw "Timestamp Expired";
    }

    return sh;
}

function generateExpectedSignature(sh: signedHeader, preSharedKey: string, payload: string) {
    var tmp = sh.timestamp.toLocaleString().split(',').join('') + "," + payload;
    return crypto.enc.Hex.stringify(crypto.HmacSHA256(tmp, crypto.enc.Hex.parse(preSharedKey)));
}