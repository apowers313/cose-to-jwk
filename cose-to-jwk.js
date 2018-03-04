module.exports = coseToJwk;

function coseToJwk(coseMap) {
    console.log("PARSING COSE");
    console.log("coseMap", coseMap);

    // main COSE labels
    // defined here: https://tools.ietf.org/html/rfc8152#section-7.1
    const coseLabels = {
        "1": {
            name: "kty",
            values: {
                "2": "EC2",
                "3": "RSA"
            }
        },
        "2": {
            name: "kid",
            values: {}
        },
        "3": {
            name: "alg",
            values: {
                "-7": "ECDSA_w_SHA256",
                "-8": "EdDSA",
                "-35": "ECDSA_w_SHA384",
                "-36": "ECDSA_w_SHA512"
            }
        },
        "4": {
            name: "key_ops",
            values: {}
        },
        "5": {
            name: "base_iv",
            values: {}
        }
    };

    // key-specific parameters
    const keyParamList = {
        // ECDSA key parameters
        // defined here: https://tools.ietf.org/html/rfc8152#section-13.1.1
        "EC2": {
            "-1": {
                name: "crv",
                values: {
                    "1": "P-256",
                    "2": "P-384",
                    "3": "P-521",
                    "4": "X25519",
                    "5": "X448",
                    "6": "Ed25519",
                    "7": "Ed448"
                }
            },
            "-2": {
                name: "x"
                // value = Buffer
            },
            "-3": {
                name: "y"
                // value = Buffer
            },
            "-4": {
                name: "d"
                // value = Buffer
            }
        },
        // RSA key parameters
        // defined here: https://tools.ietf.org/html/rfc8230#section-4
        "RSA": {
            "-1": {
                name: "n"
                // value = Buffer
            },
            "-2": {
                name: "e"
                // value = Buffer
            },
            "-3": {
                name: "d"
                // value = Buffer
            },
            "-4": {
                name: "p"
                // value = Buffer
            },
            "-5": {
                name: "q"
                // value = Buffer
            },
            "-6": {
                name: "dP"
                // value = Buffer
            },
            "-7": {
                name: "dQ"
                // value = Buffer
            },
            "-8": {
                name: "qInv"
                // value = Buffer
            },
            "-9": {
                name: "other"
                // value = Array
            },
            "-10": {
                name: "r_i"
                // value = Buffer
            },
            "-11": {
                name: "d_i"
                // value = Buffer
            },
            "-12": {
                name: "t_i"
                // value = Buffer
            }
        }

    };

    var extraMap = new Map();

    var retKey = {};

    // parse main COSE labels
    for (let kv of coseMap) {
        let key = kv[0].toString();
        let value = kv[1].toString();

        if (!coseLabels[key]) {
            extraMap.set(kv[0], kv[1]);
            continue;
        }

        let name = coseLabels[key].name;
        if (coseLabels[key].values[value]) value = coseLabels[key].values[value];
        retKey[name] = value;
    }

    var keyParams = keyParamList[retKey.kty];
    console.log("keyParams", keyParams);

    // parse key-specific parameters
    for (let kv of extraMap) {
        let key = kv[0].toString();
        let value = kv[1];

        if (!keyParams[key]) {
            throw new Error("unknown COSE key label: " + retKey.kty + " " + key);
        }
        console.log("key", key);
        let name = keyParams[key].name;
        console.log("name", name);

        if (keyParams[key].values) {
            value = keyParams[key].values[value.toString()];
        }

        retKey[name] = value;
    }

    console.log("returning", retKey);
    return retKey;
}