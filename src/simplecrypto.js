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
    window.indexedDB = window.indexedDB || window.webkitIndexedDB || window.mozIndexedDB || window.msIndexedDB;
        
    var config = {
        aesCipher: "AES-CBC",
        aesLength: 128,
        aesIvLength: 16,
        hmacOptions: {
            name: "HMAC",
            hash: { name: "SHA-256" }
        },

        rsaEncryptCipher: "RSA-OAEP",
        rsaSignCipher: "RSASSA-PKCS1-v1_5", 
        rsaLength: 2048,
        rsaHash: "SHA-256"
    };

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
            };
        }
    }

    var next = function (func, errorMsg, errorFunc, nextFunc) {
        return func.bind(null,
            function (err) {
                console.error(errorMsg, err);
                errorFunc(err);
            },
            nextFunc);
    };


    var _asym = {
        generateEncryptKeys: function(onError, onSuccess) {
            wrap(window.crypto.subtle.generateKey(
                    {
                        name: config.rsaEncryptCipher,
                        modulusLength: config.rsaLength,
                        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                        hash: { name: config.rsaHash }
                    },
                    true,
                    ["encrypt", "decrypt"]
                ), 
                onError,
                onSuccess
            );        
        },
        generateSignKeys: function (onError, onSuccess) {
            wrap(window.crypto.subtle.generateKey(
                    {
                        name: config.rsaSignCipher,
                        modulusLength: config.rsaLength,
                        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                        hash: { name: config.rsaHash }
                    },
                    true,
                    ["sign", "verify"]
                ), 
                onError,
                onSuccess
            );
        },
        
        importEncryptPrivateKey: function(jwk, onError, onSuccess) {
            wrap(window.crypto.subtle.importKey(
                    "jwk",
                    jwk,
                    { name: config.rsaEncryptCipher, hash: { name: config.rsaHash } },
                    false,
                    ["decrypt"] 
                ), onError,
                function (privateKey) {
                    onSuccess(privateKey);
                }
            );  
        },
        importSignPrivateKey: function (jwk, onError, onSuccess) {
            wrap(window.crypto.subtle.importKey(
                    "jwk",
                    jwk,
                    { name: config.rsaSignCipher, hash: { name: config.rsaHash } },
                    false,
                    ["sign"]
                ), onError,
                function (privateKey) {
                    onSuccess(privateKey);
                }
            );
        },        
        exportKey: function(key, onError, onSuccess) {
            wrap(window.crypto.subtle.exportKey(
                    "jwk",
                    key
                ), onError,
                function (jwk) {
                    onSuccess(jwk);
                }
            );
        },
        
        sign: function (data, key, onError, onSuccess) {
            wrap(window.crypto.subtle.sign(
                    { name: config.rsaSignCipher, hash: config.rsaHash },
                    key, 
                    data
                ),
                onError,
                function (signature) {
                    onSuccess(signature);
                }
            );
        },

        verifySignature: function(key, signature, data, onError, onSuccess) {
            wrap(window.crypto.subtle.verify(
                    { name: config.rsaSignCipher, hash: config.rsaHash },
                    key,
                    signature,
                    data
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
        },
        
        encrypt: function (publicKey, data, onError, onSuccess) {
            wrap(window.crypto.subtle.encrypt(
                    { name: config.rsaEncryptCipher, hash: config.rsaHash },
                    publicKey,
                    data
                ),
                onError,
                function (encrypted) {
                    onSuccess(encrypted);
                }
            );
        },
        
        decrypt: function(privateKey, data, onError, onSuccess) {
             wrap(window.crypto.subtle.decrypt(
                    { name: config.rsaEncryptCipher, hash: config.rsaHash },
                    privateKey,
                    data
             ),
             onError,
             function (keys) {
                 onSuccess(keys);
             });
        },
        
        aesEncrypt: function(data, onError, onSuccess) {                        
            simpleCrypto.sym.genKeysAndEncrypt(data, onError, function (aesDict) {
                var combinedKeys = combineBuffers(aesDict.keys.aesKey, aesDict.keys.hmacKey);
                onSuccess(combinedKeys, aesDict.data);
            });
        },
        
        aesDecrypt: function(combinedkeys, data, onError, onSuccess) {
            // todo, check sizes              
            var split = config.aesLength / 8;
            var aesKey = new Uint8Array(combinedkeys, 0, split);
            var hmacKey = new Uint8Array(combinedkeys, split);
            simpleCrypto.sym.decrypt(data, {aesKey: aesKey, hmacKey: hmacKey}, onError, onSuccess);
        }
    }


    var simpleCrypto = {

        asym : {
            
            generateKeys: function(onError, onSuccess) {
                simpleCrypto.asym.generateEncryptKey(onError, function(encryptKey) {
                    simpleCrypto.asym.generateSignKey(onError, function(signKey) {
                        onSuccess({encrypt: encryptKey, sign: signKey});    
                    }); 
                });  
            },
            
            generateEncryptKey: function (onError, onSuccess) {

                _asym.generateEncryptKeys(onError.bind(null, "Could not generate encrypt key"), function(keys) {
                 _asym.exportKey(keys.publicKey, onError.bind(null, "Could not export public encrypt key"), function(publicJwk) {
                  _asym.exportKey(keys.privateKey, onError.bind(null, "Could not export private encrypt key"), function(privateJwk){
                   _asym.importEncryptPrivateKey(privateJwk, onError.bind(null, "Could not import private encrypt key"), function(privateKey) {

                     onSuccess({privateKey: privateKey, publicKey: keys.publicKey, 
                                privateJwk: privateJwk, publicJwk: publicJwk});

                   });    
                  });    
                 });
                });
            },

            generateSignKey: function (onError, onSuccess) {

                _asym.generateSignKeys(onError.bind(null, "Could not generate sign key"), function(keys) {
                 _asym.exportKey(keys.publicKey, onError.bind(null, "Could not export public sign key"), function(publicJwk) {
                  _asym.exportKey(keys.privateKey, onError.bind(null, "Could not export private sign key"), function(privateJwk){
                   _asym.importSignPrivateKey(privateJwk, onError.bind(null, "Could not import private sign key"), function(privateKey) {

                     onSuccess({privateKey: privateKey, publicKey: keys.publicKey, 
                                privateJwk: privateJwk, publicJwk: publicJwk});

                   });    
                  });    
                 });
                });
            },

            decrypt: function (decryptKey, dict, onError, onSuccess) {
                _asym.decrypt(decryptKey, dict.encryptedKeys, onError.bind(null, "Could not decrypt keys"), function(combinedKeys){
                    _asym.aesDecrypt(combinedKeys, dict.data, onError, onSuccess);
                });
            },


            verifyAndDecrypt: function (decryptKey, verifyKey, dict, onError, onSuccess) {
                // verify signature of encrypted keys
                // decrypt keys
                // verify signature of decrypted keys
                // decrypt data 
                _asym.verifySignature(verifyKey, dict.encryptedKeysSignature, dict.encryptedKeys, onError.bind(null, "Could not verify encrypted keys"), function(){
                 _asym.decrypt(decryptKey, dict.encryptedKeys, onError.bind(null, "Could not decrypt keys"), function(combinedKeys){
                  _asym.verifySignature(verifyKey, dict.keysSignature, combinedKeys, onError.bind(null, "Could not verify keys"), function(){
                   _asym.aesDecrypt(combinedKeys, dict.data, onError, onSuccess);
                   });
                 });
                });
            },
            
            encrypt: function(encryptKey, data, onError, onSuccess) {
                _asym.aesEncrypt(data, onError.bind(null, "Could not encrypt data"), function(combinedKeys, encrypted){
                 _asym.encrypt(encryptKey, combinedKeys, onError.bind("Could not encrypt AES keys"), function(encryptedKeys) {
                  onSuccess({
                    // symmetric encryption output 
                    data: encrypted,
                    // encrypted symmetric encryption keys 
                    encryptedKeys: encryptedKeys,
                  });         
                 });           
                });    
            },

            encryptAndSign: function (encryptKey, signKey, data, onError, onSuccess) {
                // encrypt data
                // sign keys
                // encrypt keys
                // sign encrypted keys
                _asym.aesEncrypt(data, onError.bind(null, "Could not encrypt data"), function(combinedKeys, encrypted){
                 _asym.sign(combinedKeys, signKey, onError.bind(null, "Could not sign AES keys"), function(keysSignature) {
                  _asym.encrypt(encryptKey, combinedKeys, onError.bind("Could not encrypt AES keys"), function(encryptedKeys) {
                   _asym.sign(encryptedKeys, signKey, onError.bind(null, "Could not sign encrypted AES keys"), function(encryptedKeysSignature) {
                    onSuccess({
                        // symmetric encryption output 
                        data: encrypted,
                        // encrypted symmetric encryption keys 
                        encryptedKeys: encryptedKeys,
                        // signatures of plain and encryped symmetric encryption keys
                        keysSignature: keysSignature, encryptedKeysSignature: encryptedKeysSignature
                    });         
                   });       
                  });
                 })    
                });
                
            },
        },

        sym: {
            
            generateKeys: function(onError, onSuccess) {
                var result = {};

                var generateKeyAES = function (_onError, _onSuccess) {                   
                    wrap(window.crypto.subtle.generateKey(
                            { name: config.aesCipher, length: config.aesLength },
                            true,
                            ["encrypt", "decrypt"]
                        ),
                        _onError,
                        function (aesKey) {
                            result["aesKeyObj"] = aesKey;
                            _onSuccess();
                        }
                    );
                };

                var generateKeyHMAC = function (_onError, _onSuccess) {
                    wrap(window.crypto.subtle.generateKey(
                            config.hmacOptions,
                            true,
                            ["sign", "verify"]
                        ),
                        _onError,
                        function (hmacKey) {
                            result["hmacKeyObj"] = hmacKey;
                            _onSuccess();
                        }
                    );
                };
                
                
                var exportKeyAES = function (_onError, _onSuccess) {
                    wrap(window.crypto.subtle.exportKey("raw", result.aesKeyObj),
                        _onError,
                        function (aesKey) {
                            result["aesKey"] = aesKey;
                            _onSuccess();
                        }
                    );
                };

                var exportKeyHMAC = function (_onError, _onSuccess) {
                    wrap(window.crypto.subtle.exportKey("raw", result.hmacKeyObj),
                        _onError,
                        function (hmacKey) {
                            result["hmacKey"] = hmacKey;
                            _onSuccess();
                        }
                    );
                };
                
                next(generateKeyAES, "Could not generate AES key", onError,
                next(generateKeyHMAC, "Could not generate HMAC key", onError,
                next(exportKeyAES, "Could not export AES key", onError, 
                next(exportKeyHMAC, "Could not export HMAC key", onError,
                    function () {
                        onSuccess(result);
                    }
                ))))();
            },
            
            importKeys: function(keys, onError, onSuccess) {
                if (!keys || !("aesKey" in keys) || !("hmacKey" in keys)) {    
                    onError("Missing keys");
                    return;
                }
                
                // keys already has cached imported object
                if (("aesKeyObj" in keys) && ("hmacKeyObj" in keys)) {
                    onSuccess(keys);
                    return;
                }
                
                var importKeyAES = function (_onError, _onSuccess) {     
                    wrap(window.crypto.subtle.importKey(
                            "raw",
                            keys.aesKey,
                            { name: config.aesCipher },
                            false,
                            ["encrypt", "decrypt"]),
                        _onError,
                        function (aesKeyObj) {
                            keys["aesKeyObj"] = aesKeyObj;
                            _onSuccess();
                        }
                    );               
                };
                var importKeyHMAC = function(_onError, _onSuccess) {
                    wrap(window.crypto.subtle.importKey(
                            "raw",
                            keys.hmacKey,
                            config.hmacOptions,
                            false,
                            ["sign", "verify"]),
                        _onError,
                        function (hmacKeyObj) {
                            keys["hmacKeyObj"] = hmacKeyObj;
                            _onSuccess();
                        }
                    );
                };
                
                next(importKeyAES, "Could not import AES key", onError, 
                next(importKeyHMAC, "Could not import HMAC key", onError,
                    function () {
                        onSuccess();
                    }
                ))();
                
            },
            
            genKeysAndEncrypt: function(data, onError, onSuccess) {
                simpleCrypto.sym.generateKeys(onError, function(keys) {
                    simpleCrypto.sym.encrypt(data, keys, onError, onSuccess);
                });
            },
            
            encrypt: function (data, keys, onError, onSuccess) {

                var result = {};
                
                var getKeys = function (_onError, _onSuccess) { 
                   simpleCrypto.sym.importKeys(keys, _onError, _onSuccess);
                };

                var encryptAES = function (_onError, _onSuccess) {
                    var iv;
                    if ("iv" in keys) {
                        iv = keys.iv; 
                    }
                    else {
                        iv = window.crypto.getRandomValues(new Uint8Array(config.aesIvLength));
                    }
                    wrap(window.crypto.subtle.encrypt(
                            { name: config.aesCipher, iv: iv },
                            keys.aesKeyObj,
                            data
                        ),
                        _onError,
                        function (encrypted) {
                            var combined = combineBuffers(iv, encrypted);
                            result["cipherdata"] = combined;
                            _onSuccess();
                        }
                    );
                };

                var signHMAC = function (_onError, _onSuccess) {
                    wrap(window.crypto.subtle.sign(
                            config.hmacOptions,
                            keys.hmacKeyObj,
                            result.cipherdata
                        ),
                        _onError,
                        function (hmac) {
                            result["hmac"] = hmac;
                            _onSuccess();
                        }
                    );
                };


                next(getKeys, "Could not get keys", onError,
                next(encryptAES, "Could not AES Encrypt", onError,
                next(signHMAC, "Could not HMAC sign", onError,
                    function () {
                        var data = { cipherdata: result.cipherdata, hmac: result.hmac };
                        onSuccess({ keys: keys, data: data });
                    }
                )))();

            },


            decrypt: function (data, keys, onError, onSuccess) {
     
                var getKeys = function (_onError, _onSuccess) {
                    simpleCrypto.sym.importKeys(keys, _onError, _onSuccess);
                };
                
                var verifyHMAC = function (_onError, _onSuccess) {
                    wrap(window.crypto.subtle.verify(
                            config.hmacOptions,
                            keys.hmacKeyObj,
                            data.hmac,
                            data.cipherdata),
                         _onError,
                         function (isValid) {
                             if (!isValid) {
                                 _onError();
                             }
                             else {
                                 _onSuccess();
                             }
                         }
                    );
                };

                var decryptAES = function (_onError, _onSuccess) {
                    var iv = new Uint8Array(data.cipherdata, 0, 16);
                    var encrypted = new Uint8Array(data.cipherdata, 16);

                    wrap(window.crypto.subtle.decrypt(
                            { name: config.aesCipher, iv: iv },
                            keys.aesKeyObj,
                            encrypted
                        ),
                        _onError,
                        _onSuccess
                    );
                };

                next(getKeys, "Could not get keys", onError,
                next(verifyHMAC, "Could not verify HMAC key", onError,
                next(decryptAES, "Could not AES decrypt", onError,
                    function (decrypted) {
                        onSuccess(decrypted);
                    }
                )))();
            }
        }
    };
    var dbUtil = {
        _version: 1,
        _openDB: function(onError, onSuccess, func) {
            var request = indexedDB.open("simplecrypto", this._version);

            request.onupgradeneeded = function (e) {
                var db = e.target.result;
                e.target.transaction.onerror = function (event) {
                    console.log("transaction failure", event);
                };
                db.createObjectStore("keys");
            };

            request.onsuccess = function (e) {
                var db = e.target.result;
               
                func(db, function() {
                    db.close();
                })
                db.transaction(["keys"], "readwrite").objectStore("keys").get("RSA");
            };

            request.onerror = function (event) {
                onError("Error opening DB", event);
            };
        },   
        store: function(key, value, onError, onSuccess) {
            this._openDB(onError, onSuccess, function(db, closeDB) {
                var request = db.transaction(["keys"], "readwrite").objectStore("keys").put(value, key);
                request.onsuccess = function(){
                    closeDB();
                    onSuccess();
                };
                request.onerror = function(event) {
                    closeDB();
                    onError("Error storing value", event);
                };
            });
        },
        fetch: function(key, onError, onSuccess) {
            this._openDB(onError, onSuccess, function(db, closeDB) {
                var request = db.transaction(["keys"], "readonly").objectStore("keys").get(key);
                request.onsuccess = function(){
                    closeDB();
                    onSuccess(request.result);
                };
                request.onerror = function(event) {
                    closeDB();
                    onError("Error storing value", event);
                };
            });
        }
    }
    simpleCrypto.db = dbUtil;
    
    return simpleCrypto;
}));