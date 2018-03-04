const coseToJwk = require("../cose-to-jwk");
const assert = require("chai").assert;

const coseArray = [
    0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, 0xBB, 0x11, 0xCD, 0xDD, 0x6E, 0x9E,
    0x86, 0x9D, 0x15, 0x59, 0x72, 0x9A, 0x30, 0xD8, 0x9E, 0xD4, 0x9F, 0x36, 0x31, 0x52, 0x42, 0x15,
    0x96, 0x12, 0x71, 0xAB, 0xBB, 0xE2, 0x8D, 0x7B, 0x73, 0x1F, 0x22, 0x58, 0x20, 0xDB, 0xD6, 0x39,
    0x13, 0x2E, 0x2E, 0xE5, 0x61, 0x96, 0x5B, 0x83, 0x05, 0x30, 0xA6, 0xA0, 0x24, 0xF1, 0x09, 0x88,
    0x88, 0xF3, 0x13, 0x55, 0x05, 0x15, 0x92, 0x11, 0x84, 0xC8, 0x6A, 0xCA, 0xC3
];

const xArray = [
    0xbb, 0x11, 0xcd, 0xdd, 0x6e, 0x9e, 0x86, 0x9d, 0x15, 0x59, 0x72, 0x9a, 0x30, 0xd8, 0x9e, 0xd4,
    0x9f, 0x36, 0x31, 0x52, 0x42, 0x15, 0x96, 0x12, 0x71, 0xab, 0xbb, 0xe2, 0x8d, 0x7b, 0x73, 0x1f
];

const yArray = [
    0xdb, 0xd6, 0x39, 0x13, 0x2e, 0x2e, 0xe5, 0x61, 0x96, 0x5b, 0x83, 0x05, 0x30, 0xa6, 0xa0, 0x24,
    0xf1, 0x09, 0x88, 0x88, 0xf3, 0x13, 0x55, 0x05, 0x15, 0x92, 0x11, 0x84, 0xc8, 0x6a, 0xca, 0xc3
];

const xBuf = Buffer.from(xArray);
const yBuf = Buffer.from(yArray);

const coseBuffer = Buffer.from(coseArray);
const coseUint8Array = new Uint8Array(coseBuffer);
const coseUint16Array = new Uint16Array(coseBuffer);
const coseArrayBuffer = coseUint8Array.buffer;

function bufComp(a, b) {
    var len = a.length;

    if (len !== b.length) {
        return false;
    }

    for (var i = 0; i < len; i++) {
        if (a.readUInt8(i) !== b.readUInt8(i)) {
            return false;
        }
    }

    return true;
}


describe("cose-to-jwk", function() {
    it("can convert ArrayBuffer", function() {
        var ret = coseToJwk(coseArrayBuffer);
        assert.instanceOf(ret, Object);
        assert.strictEqual(ret.kty, "EC");
        assert.strictEqual(ret.crv, "P-256");
        assert.instanceOf(ret.x, Buffer);
        assert.instanceOf(ret.y, Buffer);
    });

    it("can convert Uint8Array", function() {
        var ret = coseToJwk(coseUint8Array);
        assert.instanceOf(ret, Object);
        assert.strictEqual(ret.kty, "EC");
        assert.strictEqual(ret.crv, "P-256");
        assert.instanceOf(ret.x, Buffer);
        assert.instanceOf(ret.y, Buffer);
    });

    it.skip("can convert Uint16Array", function() {
        var ret = coseToJwk(coseUint16Array);
        assert.instanceOf(ret, Object);
        assert.strictEqual(ret.kty, "EC");
        assert.strictEqual(ret.crv, "P-256");
        assert.instanceOf(ret.x, Buffer);
        assert.instanceOf(ret.y, Buffer);
    });

    it("can convert Array", function() {
        var ret = coseToJwk(coseArray);
        assert.instanceOf(ret, Object);
        assert.strictEqual(ret.kty, "EC");
        assert.strictEqual(ret.crv, "P-256");
        assert.instanceOf(ret.x, Buffer);
        assert.instanceOf(ret.y, Buffer);
    });

    it("ECDSA", function() {
        var ret = coseToJwk(coseBuffer);
        assert.instanceOf(ret, Object);
        assert.strictEqual(ret.kty, "EC");
        assert.strictEqual(ret.crv, "P-256");
        assert.instanceOf(ret.x, Buffer);
        assert.instanceOf(ret.y, Buffer);

        assert(bufComp(ret.x, xBuf), "ECDSA x bytes are correct");
        assert(bufComp(ret.y, yBuf), "ECDSA y bytes are correct");
    });
});