(function (root, factory) {
    if (typeof define === "function" && define.amd) {
        define(factory);
    } else if (typeof module === "object" && module.exports) {
        module.exports = factory();
    } else {
        root.simpleCrypto = factory();
    }
}(this, function () {
    window.crypto = window.crypto || window.msCrypto;
    window.crypto.subtle = window.crypto.subtle || window.crypto.webkitSubtle;
        
    var config = {
        aesCipher: "AES-CBC",
        aesLength: 128,
        aesIvLength: 16,

        rsaEncryptCipher: "RSA-OAEP",
        rsaSignCipher: "RSASSA-PKCS1-v1_5", 
        rsaLength: 2048,
        rsaHash: "SHA-256",

        hmacOptions: {
            name: "HMAC",
            hash: { name: "SHA-256" }
        },

    }

    function combineBuffers(buffer1, buffer2) {
        var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
        tmp.set(new Uint8Array(buffer1), 0);
        tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
        return tmp.buffer;
    }

    function wrap(result, onError, onSuccess) {
        if (typeof result.then === "function") {
            result.catch(onError).then(onSuccess);
        }
        else {
            result.onerror = onError;
            result.oncomplete = function (event) {
                onSuccess(event.target.result);
            }
        }
    }

    var next = function (func, errorMsg, errorFunc, nextFunc) {
        return func.bind(null,
            function (err) {
                console.error(errorMsg, err);
                errorFunc(err);
            },
            nextFunc);
    }


    var simpleCrypto = {

        asym : { 
            generateEncryptKey: function (onError, onSuccess) {

                var scope = {};

                var generateKey = function (onError, onSuccess) {
                    wrap(window.crypto.subtle.generateKey(
                            {
                                name: config.rsaEncryptCipher,
                                modulusLength: config.rsaLength,
                                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                                hash: { name: config.rsaHash }
                            },
                            true,
                            ["encrypt", "decrypt"]
                        ), onError,
                        function (encryptKeys) {
                            scope["encryptKeys"] = encryptKeys;
                            onSuccess();
                        }
                    );
                };

                var exportPrivateKey = function(onError, onSuccess) {
                    wrap(window.crypto.subtle.exportKey(
                            "jwk",
                            scope.encryptKeys.privateKey
                        ), onError,
                        function (privateJwk) {
                            scope["privateJwk"] = privateJwk;
                            onSuccess();
                        }
                    );
                };

                var exportPublicKey = function (onError, onSuccess) {
                    wrap(window.crypto.subtle.exportKey(
                            "jwk",
                            scope.encryptKeys.publicKey
                        ), onError,
                        function (publicJwk) {
                            scope["publicJwk"] = publicJwk;
                            onSuccess();
                        }
                    );
                };

                var importPrivateKey = function (onError, onSuccess) {
                    wrap(window.crypto.subtle.importKey(
                            "jwk",
                            scope.privateJwk,
                            { name: config.rsaEncryptCipher, hash: { name: config.rsaHash } },
                            false,
                            ["decrypt"] 
                        ), onError,
                        function (privateKey) {
                            scope["privateKey"] = privateKey;
                            onSuccess();
                        }
                    )
                }

                next(generateKey, "Could not generate encrypt key", onError,
                next(exportPrivateKey, "Could not export private encrypt key", onError,
                next(importPrivateKey, "Could not import private encrypt key", onError,
                next(exportPublicKey, "Could not export public encrypt key", onError,
                function () {
                    onSuccess({privateKey: scope.privateKey, publicKey: scope.encryptKeys.publicKey, 
                                privateJwk: scope.privateJwk, publicJwk: scope.publicJwk});

                }
                ))))();
            },

            generateSignKey: function (onError, onSuccess) {

                var scope = {};

                var generateKey = function (onError, onSuccess) {
                    wrap(window.crypto.subtle.generateKey(
                            {
                                name: config.rsaSignCipher,
                                modulusLength: config.rsaLength,
                                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                                hash: { name: config.rsaHash }
                            },
                            true,
                            ["sign", "verify"]
                        ), onError,
                        function (encryptKeys) {
                            console.log("1.1");
                            scope["signKeys"] = encryptKeys;
                            onSuccess();
                        }
                    );
                };

                var exportPrivateKey = function (onError, onSuccess) {
                    console.log("1.2a", scope.signKeys.privateKey);
                    wrap(window.crypto.subtle.exportKey(
                            "jwk",
                            scope.signKeys.privateKey
                        ), onError,
                        function (privateJwk) {
                            console.log("1.2");
                            scope["privateJwk"] = privateJwk;
                            onSuccess();
                        }
                    );
                };

                var exportPublicKey = function (onError, onSuccess) {
                    wrap(window.crypto.subtle.exportKey(
                            "jwk",
                            scope.signKeys.publicKey
                        ), onError,
                        function (publicJwk) {
                            console.log("1.3");
                            scope["publicJwk"] = publicJwk;
                            onSuccess();
                        }
                    );
                };

                var importPrivateKey = function (onError, onSuccess) {
                    wrap(window.crypto.subtle.importKey(
                            "jwk",
                            scope.privateJwk,
                            { name: config.rsaSignCipher, hash: { name: config.rsaHash } },
                            false,
                            ["sign"]
                        ), onError,
                        function (privateKey) {
                            console.log("1.4");
                            scope["privateKey"] = privateKey;
                            onSuccess();
                        }
                    )
                }

                next(generateKey, "Could not generate encrypt key", onError,
                next(exportPrivateKey, "Could not export private encrypt key", onError,
                next(importPrivateKey, "Could not import private encrypt key", onError,
                next(exportPublicKey, "Could not export public encrypt key", onError,
                function () {
                    onSuccess({privateKey: scope.privateKey, publicKey: scope.signKeys.publicKey, 
                                privateJwk: scope.privateJwk, publicJwk: scope.publicJwk});
                }
                ))))(); 
            },

            verifyAndDecrypt: function (myEncryptPrivateKey, sendersSignPublicKey, dict, onError, onSuccess) {

                var scope = {};

                var verifyEncryptedKeys = function (onError, onSuccess) {
                    wrap(window.crypto.subtle.verify(
                            { name: config.rsaSignCipher, hash: config.rsaHash },
                            sendersSignPublicKey,
                            dict.encryptedKeysSignature,
                            dict.encryptedKeys
                    ),
                    onError,
                    function (isValid) {
                        if (!isValid) {
                            onError();
                        }
                        else {
                            onSuccess();
                        }
                    });
                };

                var decryptKeys = function (onError, onSuccess) {
                     wrap(window.crypto.subtle.decrypt(
                            { name: config.rsaEncryptCipher, hash: config.rsaHash },
                            myEncryptPrivateKey,
                            dict.encryptedKeys
                     ),
                     onError,
                     function (keys) {
                         scope["combinedKeys"] = keys;
                         onSuccess();
                     });
                }

                var verifyKeys = function (onError, onSuccess) {
                    wrap(window.crypto.subtle.verify(
                            { name: config.rsaSignCipher, hash: config.rsaHash },
                            sendersSignPublicKey,
                            dict.keysSignature,
                            scope.combinedKeys
                    ),
                    onError,
                    function (isValid) {
                        if (!isValid) {
                            onError();
                        }
                        else {
                            onSuccess();
                        }
                    });
                };


                next(verifyEncryptedKeys, "Could not verify encrypted key", onError,
                next(decryptKeys, "Could not decrypt keys", onError,
                next(verifyKeys, "Could not verify keys", onError,
                    function () {
                        var keys = scope.combinedKeys;
                        var split = config.aesLength / 8;
                        var aesKey = new Uint8Array(keys, 0, split);
                        var hmacKey = new Uint8Array(keys, split);

                        dict["aesKey"] = aesKey;
                        dict["hmacKey"] = hmacKey;

                        simpleCrypto.sym.decrypt(dict, onError, onSuccess);
                    }
               )))();
            },

            encryptAndSign: function (recepientsEncryptPublicKey, mySignPrivateKey, data, onError, onSuccess) {

                var scope;

                var encryptData = function(onError, onSuccess) {
                        
                    simpleCrypto.sym.encrypt(data, onError, function (aesDict) {
                        scope = aesDict;
                        var combinedKeys = combineBuffers(aesDict.aesKey, aesDict.hmacKey);
                        scope["combinedKeys"] = combinedKeys;
                        scope["cipherdata"] = aesDict.cipherdata;
                        scope["hmac"] = aesDict.hmac;
                        onSuccess();
                    });
                }


                var encryptKeys = function (onError, onSuccess) {
                    wrap(window.crypto.subtle.encrypt(
                            { name: config.rsaEncryptCipher, hash: config.rsaHash },
                            recepientsEncryptPublicKey,
                            scope.combinedKeys
                        ),
                        onError,
                        function (encryptedKeys) {
                            scope["encryptedKeys"] = encryptedKeys;
                            onSuccess();
                        }
                    );
                }

                var signKeys = function (onError, onSuccess) {
                    wrap(window.crypto.subtle.sign(
                            { name: config.rsaSignCipher, hash: config.rsaHash },
                            mySignPrivateKey,
                            scope.combinedKeys,
                            data
                        ),
                        onError,
                        function (keysSignature) {
                            scope["keysSignature"] = keysSignature;
                            onSuccess();
                        }
                    );
                }
                var signEncryptedKeys = function (onError, onSuccess) {
                    wrap(window.crypto.subtle.sign(
                            { name: config.rsaSignCipher, hash: config.rsaHash },
                            mySignPrivateKey,
                            scope.encryptedKeys,
                            data
                        ),
                        onError,
                        function (encryptedKeysSignature) {
                            scope["encryptedKeysSignature"] = encryptedKeysSignature;
                            onSuccess();
                        }
                    );
                }


                next(encryptData, "Could not encrypt data", onError,
                next(signKeys, "Could not sign AES keys", onError,
                next(encryptKeys, "Could not encrypt AES keys", onError,
                next(signEncryptedKeys, "Could not sign encrypted AES keys", onError,
                    function () {                       
                        onSuccess({
                            // symmetric encryption output 
                            cipherdata: scope.cipherdata, hmac: scope.hmac,
                            // encrypted symmetric encryption keys 
                            encryptedKeys: scope.encryptedKeys,
                            // signatures of plain and encryped symmetric encryption keys
                            keysSignature: scope.keysSignature, encryptedKeysSignature: scope.encryptedKeysSignature
                        });
                    }
                ))))();

            },
        },

        sym: {
            encrypt: function (data, onError, onSuccess) {

                var result = {};

                var generateKeyAES = function (onError, onSuccess) {
                    wrap(window.crypto.subtle.generateKey(
                            { name: config.aesCipher, length: config.aesLength },
                            true,
                            ["encrypt", "decrypt"]
                        ),
                        onError,
                        function (aesKey) {
                            result["aesKey"] = aesKey;
                            onSuccess();
                        }
                    )
                }

                var generateKeyHMAC = function (onError, onSuccess) {
                    wrap(window.crypto.subtle.generateKey(
                            config.hmacOptions,
                            true,
                            ["sign", "verify"]
                        ),
                        onError,
                        function (hmacKey) {
                            result["hmacKey"] = hmacKey;
                            onSuccess();
                        }
                    );
                }

                var encryptAES = function (onError, onSuccess) {
                    var iv = window.crypto.getRandomValues(new Uint8Array(config.aesIvLength));
                    wrap(window.crypto.subtle.encrypt(
                            { name: config.aesCipher, iv: iv },
                            result.aesKey,
                            data
                        ),
                        onError,
                        function (encrypted) {
                            var combined = combineBuffers(iv, encrypted);
                            result["cipherdata"] = combined;
                            onSuccess();
                        }
                    )
                }

                var signHMAC = function (onError, onSuccess) {
                    wrap(window.crypto.subtle.sign(
                            config.hmacOptions,
                            result.hmacKey,
                            result.cipherdata
                        ),
                        onError,
                        function (hmac) {
                            result["hmac"] = hmac;
                            onSuccess();
                        }
                    )
                }

                var exportKeyAES = function (onError, onSuccess) {
                    wrap(window.crypto.subtle.exportKey("raw", result.aesKey),
                        onError,
                        function (rawAesKey) {
                            result["rawAesKey"] = rawAesKey;
                            onSuccess();
                        }
                    );
                }

                var exportKeyHMAC = function (onError, onSuccess) {
                    wrap(window.crypto.subtle.exportKey("raw", result.hmacKey),
                        onError,
                        function (rawHmacKey) {
                            result["rawHmacKey"] = rawHmacKey;
                            onSuccess();
                        }
                    );
                }

                next(generateKeyAES, "Could not generate AES key", onError,
                next(generateKeyHMAC, "Could not generate HMAC key", onError,
                next(encryptAES, "Could not AES Encrypt", onError,
                next(signHMAC, "Could not HMAC sign", onError,
                next(exportKeyAES, "Could not export AES key", onError,
                next(exportKeyHMAC, "Could not export HMAC key", onError,
                    function () {
                        onSuccess({ aesKey: result.rawAesKey, hmacKey: result.rawHmacKey, cipherdata: result.cipherdata, hmac: result.hmac });
                    }
                ))))))();

            },

            decrypt: function (dict, onError, onSuccess) {

                var scope = {};
                var importKeyAES = function (onError, onSuccess) {
                    wrap(window.crypto.subtle.importKey(
                            "raw",
                            dict.aesKey,
                            { name: config.aesCipher },
                            false,
                            ["decrypt"]),
                        onError,
                        function (result) {
                            scope["aesKey"] = result;
                            onSuccess();
                        }
                    );
                };

                var importKeyHMAC = function (onError, onSuccess) {
                    wrap(window.crypto.subtle.importKey(
                            "raw",
                            dict.hmacKey,
                            config.hmacOptions,
                            false,
                            ["verify"]),
                        onError,
                        function (result) {
                            scope["hmacKey"] = result;
                            onSuccess();
                        }
                    );
                };

                var verifyHMAC = function (onError, onSuccess) {
                    wrap(window.crypto.subtle.verify(
                            config.hmacOptions,
                            scope.hmacKey,
                            dict.hmac,
                            dict.cipherdata),
                         onError,
                         function (isValid) {
                             if (!isValid) {
                                 onError();
                             }
                             else {
                                 onSuccess();
                             }
                         }
                    );
                };

                var decryptAES = function (onError, onSuccess) {
                    var iv = new Uint8Array(dict.cipherdata, 0, 16);
                    var encrypted = new Uint8Array(dict.cipherdata, 16);

                    wrap(window.crypto.subtle.decrypt(
                            { name: config.aesCipher, iv: iv },
                            scope.aesKey,
                            encrypted
                        ),
                        onError,
                        onSuccess
                    )
                }

                next(importKeyAES, "Could not generate AES key", onError,
                next(importKeyHMAC, "Could not import HMAC key", onError,
                next(verifyHMAC, "Could not verify HMAC key", onError,
                next(decryptAES, "Could not AES decrypt", onError,
                    function (data) {
                        onSuccess(data);
                    }
                ))))();

            }
        }
    }
    return simpleCrypto;
}));