(function (root, factory) {
    if (typeof define === "function" && define.amd) {
        define(factory);
    } else if (typeof module === "object" && module.exports) {
        module.exports = factory();
    } else {
        root.simpleCrypto = factory();
    }
}(this, function () {
    var oldSubtle = false;
    if (window.crypto && window.crypto.webkitSubtle && window.crypto.subtle === undefined){
        oldSubtle = true;
    }
    if (window.msCrypto && (window.crypto === undefined || window.crypto.subtle === undefined)){
        oldSubtle = true;
    }
    
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

        rsaLength: 2048,
        
        rsaEncryptCipher: "RSA-OAEP",
        rsaEncryptHash: "SHA-1",
        rsaSignCipher: "RSASSA-PKCS1-v1_5",
        rsaSignHash: "SHA-256"
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
    
    function bytesToString(bytes) {
        return String.fromCharCode.apply(null, new Uint8Array(bytes));
    }

    function stringToBytes(str) {
        var chars = [];
        for (var i = 0; i < str.length; ++i) {
            chars.push(str.charCodeAt(i));
        }
        return new Uint8Array(chars);
    }

    var _sym = {
        generateKeyAES: function (onError, onSuccess) {                   
            wrap(window.crypto.subtle.generateKey(
                    { name: config.aesCipher, length: config.aesLength },
                    true,
                    ["encrypt", "decrypt"]
                ),
                onError,
                function (aesKey) {
                    onSuccess(aesKey);
                }
            );
        },

        generateKeyHMAC: function (onError, onSuccess) {
            wrap(window.crypto.subtle.generateKey(
                    config.hmacOptions,
                    true,
                    ["sign", "verify"]
                ),
                onError,
                function (hmacKey) {
                    onSuccess(hmacKey);
                }
            );
        },

        importKeyAES: function (key, onError, onSuccess) {     
            wrap(window.crypto.subtle.importKey(
                    "raw",
                    key,
                    { name: config.aesCipher },
                    false,
                    ["encrypt", "decrypt"]),
                onError,
                function (keyObj) {
                    onSuccess(keyObj);
                }
            );               
        },
        importKeyHMAC: function(key, onError, onSuccess) {
            wrap(window.crypto.subtle.importKey(
                    "raw",
                    key,
                    config.hmacOptions,
                    false,
                    ["sign", "verify"]),
                onError,
                function (keyObj) {
                    onSuccess(keyObj);
                }
            );
        },
                
        exportKey: function (key, onError, onSuccess) {
            wrap(window.crypto.subtle.exportKey("raw", key),
                onError,
                function (key) {
                    onSuccess(key);
                }
            );
        },
        
        encrypt: function(key, iv, data, onError, onSuccess) {
            wrap(window.crypto.subtle.encrypt(
                    { name: config.aesCipher, iv: iv },
                    key,
                    data
                ),
                onError,
                function (encrypted) {
                    var cipherdata = combineBuffers(iv, encrypted);
                    onSuccess(cipherdata);
                }
            );
        },

        decryptAES: function (key, cipherdata, onError, onSuccess) {
            var iv = new Uint8Array(cipherdata, 0, 16);
            var encrypted = new Uint8Array(cipherdata, 16);

            wrap(window.crypto.subtle.decrypt(
                    { name: config.aesCipher, iv: iv },
                    key,
                    encrypted
                ),
                onError,
                onSuccess
            );
        },

        signHMAC: function(key, data, onError, onSuccess) {
            wrap(window.crypto.subtle.sign(
                    config.hmacOptions,
                    key,
                    data
                ),
                onError,
                function (hmac) {
                    onSuccess(hmac);
                }
            );
        }, 

        verifyHMAC: function (key, hmac, cipherdata, onError, onSuccess) {
            wrap(window.crypto.subtle.verify(
                    config.hmacOptions,
                    key,
                    hmac,
                    cipherdata),
                 onError,
                 function (isValid) {
                     if (!isValid) {
                         onError("Invalid HMAC");
                     }
                     else {
                         onSuccess();
                     }
                 }
            );
        },
    };

    var _asym = {
        generateEncryptKeys: function(onError, onSuccess) {
            wrap(window.crypto.subtle.generateKey(
                    {
                        name: config.rsaEncryptCipher,
                        modulusLength: config.rsaLength,
                        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                        hash: { name: config.rsaEncryptHash }
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
                        hash: { name: config.rsaSignHash }
                    },
                    true,
                    ["sign", "verify"]
                ), 
                onError,
                onSuccess
            );
        },
        
        importEncryptPrivateKey: function(jwk, onError, onSuccess) {
            
            if(oldSubtle) {
                jwk = stringToBytes(JSON.stringify(jwk));
            }
            
            wrap(window.crypto.subtle.importKey(
                    "jwk",
                    jwk,
                    { name: config.rsaEncryptCipher, hash: {name: config.rsaEncryptHash } },
                    false,
                    ["decrypt"] 
                ), onError,
                function (privateKey) {
                    onSuccess(privateKey);
                }
            );  
        },
        importSignPrivateKey: function (jwk, onError, onSuccess) {
            if(oldSubtle) {
                jwk = stringToBytes(JSON.stringify(jwk));
            }
            wrap(window.crypto.subtle.importKey(
                    "jwk",
                    jwk,
                    { name: config.rsaSignCipher, hash: { name: config.rsaSignHash } },
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
                    if (oldSubtle) {
                        try {
                            var fixedJwk = JSON.parse(bytesToString(jwk));
                            onSuccess(fixedJwk);
                        }
                        catch(e) {
                            onError(e.message, e);
                            return;
                        }
                    }
                    else {
                        onSuccess(jwk);
                    }
                }
            );
        },
        sign: function (key, data, onError, onSuccess) {
            wrap(window.crypto.subtle.sign(
                    { name: config.rsaSignCipher, hash: config.rsaSignHash },
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
                    { name: config.rsaSignCipher, hash: config.rsaSignHash },
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
                    { name: config.rsaEncryptCipher, hash: config.rsaEncryptHash },
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
                    { name: config.rsaEncryptCipher, hash: config.rsaEncryptHash },
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
            simpleCrypto.sym.decrypt({aesKey: aesKey, hmacKey: hmacKey}, data, onError, onSuccess);
        }
    }


    var simpleCrypto = {

        storage: {
            get: function(keyId, onError, onSuccess) {
                dbUtil.get(keyId, onError, onSuccess);    
            },
            put: function(keyId, key, onError, onSuccess) {
                dbUtil.put(keyId, key, onError, onSuccess);    
            },
            delete: function(keyId, onError, onSuccess) {
                dbUtil.delete(keyId, onError, onSuccess);
            }
        },
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

                     onSuccess({privateKey: privateKey, privateKey2:keys.privateKey, publicKey: keys.publicKey, 
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
                 _asym.sign(signKey, combinedKeys, onError.bind(null, "Could not sign AES keys"), function(keysSignature) {
                  _asym.encrypt(encryptKey, combinedKeys, onError.bind("Could not encrypt AES keys"), function(encryptedKeys) {
                   _asym.sign(signKey, encryptedKeys, onError.bind(null, "Could not sign encrypted AES keys"), function(encryptedKeysSignature) {
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

                // generate random AES and HMAC keys
                // export them in RAW format
                _sym.generateKeyAES(onError.bind(null, "Could not generate AES key"), function(aesKeyObj){
                 _sym.generateKeyHMAC(onError.bind(null, "Could not generate HMAC key"), function(hmacKeyObj){
                  _sym.exportKey(aesKeyObj, onError.bind(null, "Could not export AES key"), function(aesKey) {
                   _sym.exportKey(hmacKeyObj, onError.bind(null, "Could not export HMAC key"), function(hmacKey) {
                       onSuccess({aesKeyObj: aesKeyObj, hmacKeyObj: hmacKeyObj, aesKey: aesKey, hmacKey: hmacKey});    
                   }); }); }); });
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
                
                _sym.importKeyAES(keys.aesKey, onError.bind(null, "Could not import AES key"), function(aesKeyObj) {
                    keys["aesKeyObj"] = aesKeyObj;
                    _sym.importKeyHMAC(keys.hmacKey, onError.bind(null, "Could not import HMAC key"), function(hmacKeyObj) {
                        keys["hmacKeyObj"] = hmacKeyObj;
                        onSuccess();
                    });
                });
            },
            
            genKeysAndEncrypt: function(data, onError, onSuccess) {
                simpleCrypto.sym.generateKeys(onError, function(keys) {
                    simpleCrypto.sym.encrypt(keys, data, onError, onSuccess);
                });
            },
            
            encrypt: function (keys, data, onError, onSuccess) {

                simpleCrypto.sym.importKeys(keys, onError.bind(null, "Could not get keys"), function() {
                    var iv;
                    if ("iv" in keys) {
                        iv = keys.iv; 
                    }
                    else {
                        iv = window.crypto.getRandomValues(new Uint8Array(config.aesIvLength));
                    }
                    _sym.encrypt(keys.aesKeyObj, iv, data, onError.bind(null, "Could not AES Encrypt"), function(cipherdata){
                        _sym.signHMAC(keys.hmacKeyObj, cipherdata, onError.bind(null, "Could not HMAC sign"), function(hmac) {
                            var data = { cipherdata: cipherdata, hmac: hmac };
                            onSuccess({ keys: keys, data: data });                           
                        });  
                    });
                });
            },

            decrypt: function (keys, data, onError, onSuccess) {
                simpleCrypto.sym.importKeys(keys, onError, function(){
                    _sym.verifyHMAC(keys.hmacKeyObj, data.hmac, data.cipherdata, onError.bind(null, "Could not verify HMAC"), function(){
                        _sym.decryptAES(keys.aesKeyObj, data.cipherdata, onError.bind(null, "Could not AES decrypt"), function(data) {
                            onSuccess(data);
                        });
                    });    
                });
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
        put: function(key, value, onError, onSuccess) {
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
        get: function(key, onError, onSuccess) {
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
        },
        delete: function(key, onError, onSuccess) {
            this._openDB(onError, onSuccess, function(db, closeDB) {
                var request = db.transaction(["keys"], "readwrite").objectStore("keys").delete(key);
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