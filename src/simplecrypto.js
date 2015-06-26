(function (root, factory) {
    if (typeof define === "function" && define.amd) {
        define(factory);
    } else if (typeof module === "object" && module.exports) {
        module.exports = factory();
    } else {
        root.simpleCrypto = factory();
    }
}(this, function () {
    var oldWebkit = false;
    var oldIE = false;
    if (window.crypto && window.crypto.webkitSubtle && window.crypto.subtle === undefined){
        oldWebkit = true;
    }
    if (window.msCrypto && (window.crypto === undefined || window.crypto.subtle === undefined)){
        oldIE = true;
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
            hash: { name: "SHA-256" },
            // old webkit stores length in bytes, everything else in bits
            length: oldWebkit ? 32 : 256
        },
        
        rsaLength: 2048,
        // (rsaLength / 8) - 2 - (2 * hash length)
        rsaEncryptMax: 214,
        
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
            var iv, encrypted;
            if (cipherdata instanceof Uint8Array) {
                var offset = cipherdata.byteOffset;
                var length = cipherdata.length;
                iv = new Uint8Array(cipherdata.buffer, offset, 16);
                encrypted = new Uint8Array(cipherdata.buffer, offset + 16, length-16);
            }
            else {
                iv = new Uint8Array(cipherdata, 0, 16);
                encrypted = new Uint8Array(cipherdata, 16);
            }
            
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
            
            if(oldWebkit || oldIE) {
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
            if(oldWebkit || oldIE) {
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
                    if (oldWebkit || oldIE) {
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
            var aesKey, hmacKey, length;
            
            var aesLength = config.aesLength / 8;
            // old webkit stores length in bytes, everything else in bits
            var hmacLength = oldWebkit ? config.hmacOptions.length : (config.hmacOptions.length / 8);
            
            if (combinedkeys instanceof Uint8Array) {
                var offset = combinedkeys.byteOffset;
                length = combinedkeys.length;
                if (length != (aesLength + hmacLength)) {
                    onError("Combined keys size is incorrect", length, aesLength, hmacLength);
                    return;
                }
                aesKey = new Uint8Array(combinedkeys.buffer, offset, aesLength);
                hmacKey = new Uint8Array(combinedkeys.buffer, offset + aesLength, hmacLength);
            }
            else if (combinedkeys instanceof ArrayBuffer) {
                length = combinedkeys.byteLength;
                if (length != (aesLength + hmacLength)) {
                    onError("Combined keys size is incorrect", length, aesLength, hmacLength);
                    return;
                }
                aesKey = new Uint8Array(combinedkeys, 0, aesLength);
                hmacKey = new Uint8Array(combinedkeys, aesLength);
            }
                
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
                if (dict.aesEncrypted) {
                    _asym.decrypt(decryptKey, dict.rsaEncrypted, onError.bind(null, "Could not decrypt keys"), function(combinedKeys){
                        _asym.aesDecrypt(combinedKeys, { aesEncrypted: dict.aesEncrypted, hmac: dict.hmac }, onError, onSuccess);
                    });
                }
                else {
                    _asym.decrypt(decryptKey, dict.rsaEncrypted, onError.bind(null, "Could not RSA decrypt"), onSuccess);
                }
            },


            verifyAndDecrypt: function (decryptKey, verifyKey, dict, onError, onSuccess) {
                // verify signature of encrypted rsa data
                // decrypt rsa data
                // verify signature of decrypted rsa data
                // decrypt aes data if required
                _asym.verifySignature(verifyKey, dict.signatureOfEncrypted, dict.rsaEncrypted, onError.bind(null, "Could not verify encrypted keys"), function(){
                    _asym.decrypt(decryptKey, dict.rsaEncrypted, onError.bind(null, "Could not decrypt keys"), function(decrypted){
                        _asym.verifySignature(verifyKey, dict.signatureOfData, decrypted, onError.bind(null, "Could not verify keys"), function(){
                            if (dict.aesEncrypted) {
                                _asym.aesDecrypt(decrypted, { aesEncrypted: dict.aesEncrypted, hmac: dict.hmac }, onError, onSuccess);
                            }
                            else {
                                onSuccess(decrypted);
                            }
                        });
                    });
                });
            },
            
            _encrypt: function(encryptKey, data, rawData, onError, onSuccess) {
                
                var dataLenght = data instanceof ArrayBuffer? data.byteLength : data.length;
                if (dataLenght <= config.rsaEncryptMax) {
                    _asym.encrypt(encryptKey, data, onError.bind("Could not RSA encrypt data"), function(encrypted) {
                        rawData["data"] = data;
                        onSuccess({rsaEncrypted: encrypted});
                    });
                }
                else {
                    _asym.aesEncrypt(data, onError.bind(null, "Could not AES encrypt data"), function(combinedKeys, encrypted){
                        _asym.encrypt(encryptKey, combinedKeys, onError.bind("Could not encrypt AES keys"), function(encryptedKeys) {
                            rawData["data"] = combinedKeys;
                            onSuccess({
                                // AES encryption output 
                                aesEncrypted: encrypted.aesEncrypted, hmac: encrypted.hmac,
                                // RSA encrypted symmetric encryption keys 
                                rsaEncrypted: encryptedKeys,
                            });         
                        });           
                    });
                } 
            },
            encrypt: function(encryptKey, data, onError, onSuccess) {
                var rawData = {};
                this._encrypt(encryptKey, data, rawData, onError, onSuccess);
            },
            

            encryptAndSign: function (encryptKey, signKey, data, onError, onSuccess) {
                var rawData = {};
                // encrypt data
                // sign data
                // sign encrypted data
                this._encrypt(encryptKey, data, rawData, onError, function(encrypted) {    
                    _asym.sign(signKey, rawData.data, onError.bind(null, "Could not sign raw data"), function(signatureOfData) {
                        _asym.sign(signKey, encrypted.rsaEncrypted, onError.bind(null, "Could not sign encrypted data"), function(signatureOfEncrypted) {
                            encrypted["signatureOfData"] = signatureOfData;
                            encrypted["signatureOfEncrypted"] = signatureOfEncrypted;
                            onSuccess(encrypted);         
                        });       
                    });
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
                    _sym.encrypt(keys.aesKeyObj, iv, data, onError.bind(null, "Could not AES Encrypt"), function(aesEncrypted){
                        _sym.signHMAC(keys.hmacKeyObj, aesEncrypted, onError.bind(null, "Could not HMAC sign"), function(hmac) {
                            var data = { aesEncrypted: aesEncrypted, hmac: hmac };
                            onSuccess({ keys: keys, data: data });                           
                        });  
                    });
                });
            },

            decrypt: function (keys, data, onError, onSuccess) {
                simpleCrypto.sym.importKeys(keys, onError, function(){
                    _sym.verifyHMAC(keys.hmacKeyObj, data.hmac, data.aesEncrypted, onError.bind(null, "Could not verify HMAC"), function(){
                        _sym.decryptAES(keys.aesKeyObj, data.aesEncrypted, onError.bind(null, "Could not AES decrypt"), function(decrypted) {
                            onSuccess(decrypted);
                        });
                    });    
                });
            }
            
        }
    };

    var encoding = {
            
        VERSION: 1,
        
        LABEL_TO_INDEX: {
                    // symmetric
                    aesEncrypted : 0, hmac: 1,
                    // asymmetric
                    rsaEncrypted: 10,
                    signatureOfData: 20, signatureOfEncrypted: 21
        },
        INDEX_TO_LABEL: {
                    0: "aesEncrypted", 1: "hmac",
                    10: "rsaEncrypted",
                    20: "signatureOfData", 21: "signatureOfEncrypted"
        },
    
     
        encode: function(dict) {
    
            var size = 1;
            var numItems = 0;
            for (var label in dict) {
                if (!(label in this.LABEL_TO_INDEX)) {
                    throw "Unsupported key: " + label;
                }
                size += 5; //1 byte for key, 4 bytes for size
                size += dict[label].byteLength;
                numItems ++;
            }
    
            var buffer = new ArrayBuffer(size);
            var view = new DataView(buffer);
            var offset = 0;
            view.setUint8(offset, this.VERSION);
            offset++;
    
            for (var label in dict) {
                
                var index = this.LABEL_TO_INDEX[label]
                view.setUint8(offset, index);
                var data = dict[label];
                view.setUint32(offset + 1, data.byteLength);
                (new Uint8Array(view.buffer)).set(new Uint8Array(data), offset + 5);
                offset += 5 + data.byteLength;
            }
            return buffer;
        },
    
        decode: function(buffer) {
            var dict = {};
    
            var view = new DataView(buffer);
            var offset = 0;
            var version = view.getUint8(offset);
            offset++;
            while (offset < buffer.byteLength) {
                var index = view.getUint8(offset);
                var label = this.INDEX_TO_LABEL[index];
                var size = view.getUint32(offset + 1);
                
                // make sure we don't over allocate
                if (size > (buffer.byteLength - offset + 5)) {
                    throw "Incorrect size " + size + buffer.byteLength;
                }
                var data = new Uint8Array(view.buffer, offset + 5 , size);
                offset += 5 + data.length;
    
                dict[label] = data;
            }
            return dict;
        }
    }
    
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
    simpleCrypto.encoding = encoding;
    
    return simpleCrypto;
}));