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
            hash: { name: "SHA-1" },
            // old webkit stores length in bytes, everything else in bits
            length: oldWebkit ? 20 : 160
        },
        
        rsaLength: 2048,
        // (rsaLength / 8) - 2 - (2 * hash length)
        rsaEncryptMax: 214,
        
        rsaEncryptCipher: "RSA-OAEP",
        rsaEncryptHash: "SHA-1",
        rsaSignCipher: "RSASSA-PKCS1-v1_5",
        rsaSignHash: "SHA-256",
        
        
        pbkdf2: {
            minIterations: 20000,
            hash: "SHA-1"
        }
    };

   function wrap(result, onError, onSuccess) {
        if (typeof result.then === "function") {
            result.then(onSuccess).catch(onError);
        }
        else {
            result.onerror = onError;
            result.oncomplete = function (event) {
                onSuccess(event.target.result);
            };
        }
    }

    var util = {

        uint32toBuffer: function(value) {
            var result = new Uint8Array(4);        
            result[0] = (value & 0x000000ff);
            result[1] = (value & 0x0000ff00) >> 8;
            result[2] = (value & 0x00ff0000) >> 16;
            result[3] = (value & 0xff000000) >> 24;
            return result.buffer;
        },
        
        bufferToUint32: function(array) {
            if (array instanceof ArrayBuffer) {
                array = new Uint8Array(array);
            }
            return array[0] + (array[1] << 8) + (array[2] << 16) + (array[3] << 24);
        },
    
        combineBuffers: function(buffer1, buffer2) {
            var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
            tmp.set(new Uint8Array(buffer1), 0);
            tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
            return tmp.buffer;
        },
    
 
        
        bytesToString: function(bytes) {
            return String.fromCharCode.apply(null, new Uint8Array(bytes));
        },

        stringToBytes: function(str) {
            var chars = [];
            for (var i = 0; i < str.length; ++i) {
                chars.push(str.charCodeAt(i));
            }
            return new Uint8Array(chars);
        }
    }

    var random = {
        get : function(max) {
            var MAX_UINT16 = 65535;
            if (max > MAX_UINT16 || max < 0) {
                throw ("Invalid max value" + max);
            }
            var buffer = new Uint16Array(1);
            window.crypto.getRandomValues(buffer);
            return Math.floor(max * buffer[0] / MAX_UINT16);
        }
    };
    
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
                    var cipherdata = util.combineBuffers(iv, encrypted);
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
                onSuccess
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
                jwk = util.stringToBytes(JSON.stringify(jwk));
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
                jwk = util.stringToBytes(JSON.stringify(jwk));
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
                            // TODO: need to add key type to JWK
                            var fixedJwk = JSON.parse(util.bytesToString(jwk));
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
                var combinedKeys = util.combineBuffers(aesDict.keys.aesKey, aesDict.keys.hmacKey);
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
    },
    _pbkdf2 = {
         passwordToKey: function(password, onError, onSuccess) {
            wrap(window.crypto.subtle.importKey(
                    "raw",
                    util.stringToBytes(password),
                    {"name": "PBKDF2"},
                    false,
                    ["deriveBits"]
                ),
                onError,
                onSuccess
                );
        },
        deriveBits: function(key, length, options, onError, onSuccess) {
            var salt = options.salt || window.crypto.getRandomValues(new Uint8Array(16));
            var iterations;
            if (options.iterations) {
                if (options.iterations instanceof ArrayBuffer || options.iterations instanceof Uint8Array) {
                    iterations = util.bufferToUint32(options.iterations);
                }
                else {
                    iterations = options.iterations;
                }
            }
            else {
                iterations = (random.get(4000) + config.pbkdf2.minIterations);
            }
            wrap(window.crypto.subtle.deriveBits(
                    {
                        name: "PBKDF2",
                        salt: salt,
                        iterations: iterations,
                        hash: {name: config.pbkdf2.hash}
                    },
                    key,
                    length
                ),
                onError,
                function(derived) {
                    onSuccess({salt: salt.buffer, iterations: util.uint32toBuffer(iterations), derived: derived})
                }
            )
        },
        importKeyHMAC: function(password, onError, onSuccess) {
            wrap(window.crypto.subtle.importKey(
                    "raw",
                    util.stringToBytes(password),
                    {
                        name: "HMAC",
                        hash: { name: config.pbkdf2.hash },
                    },
                    false,
                    ["sign", "verify"]
                ),
                onError,
                onSuccess
            );
        },
        importKeyHMAC2: function(password, onError, onSuccess) {
            wrap(window.crypto.subtle.importKey(
                    "raw",
                    password,
                    {
                        name: "HMAC",
                        hash: { name: config.pbkdf2.hash },
                    },
                    false,
                    ["sign", "verify"]
                ),
                onError,
                onSuccess
            );
        },
        signHMAC: function(key, data, onError, onSuccess) {
            wrap(window.crypto.subtle.sign(
                    {
                        name: "HMAC",
                        hash: { name: config.pbkdf2.hash },
                    },
                    key,
                    data
                ),
                onError,
                onSuccess
            );
        },
        
        ua2hex: function(ua) {
            var h = '';
            for (var i = 0; i < ua.length; i++) {
                h += ua[i].toString(16) + " ";
            }
            return h;
        },
        
        compatDerive: function(password, bitLength, options, onError, onSuccess) {
            
            var salt = options.salt || window.crypto.getRandomValues(new Uint8Array(16));
            var iterations;
            if (options.iterations) {
                if (options.iterations instanceof ArrayBuffer || options.iterations instanceof Uint8Array) {
                    iterations = util.bufferToUint32(options.iterations);
                }
                else {
                    iterations = options.iterations;
                }
            }
            else {
                iterations = (random.get(4000) + config.pbkdf2.minIterations);
            }
          

            var deriveBlockLoop = function(key, U_1, U_n, counter, iterations, onError, onSuccess) {
            
                if (counter == iterations) {
                    onSuccess(U_1);
                    return;
                }

                _pbkdf2.signHMAC(key, U_n, onError, function(result) {
                    var new_U_n = new Uint8Array(result);
                    for (var i=0; i < U_1.length; i++){
                        U_1[i] ^= new_U_n[i];
                    }
                    
                    deriveBlockLoop(key, U_1, new_U_n, counter + 1, iterations, onError, onSuccess);
                });  
            }
            
            var deriveLoop = function(key, blockNum, length, salt, iterations, output, onError, onSuccess) {
                var data = util.combineBuffers(salt.buffer, new Uint8Array([0,0,0,blockNum]).buffer);
                _pbkdf2.signHMAC(key, data, onError, function(hmacBuffer) {
                    var hmac = new Uint8Array(hmacBuffer);
                    deriveBlockLoop(key, hmac, hmac, 1, iterations, onError, function(U_1) {
                        var newOutput = new Uint8Array(util.combineBuffers(output.buffer, U_1.buffer));
                        if (newOutput.length == length) {
                            onSuccess(newOutput.buffer);
                        }
                        else if (newOutput.length > length) {
                            onSuccess(newOutput.subarray(0, length).buffer);
                        }
                        else {
                            deriveLoop(key, blockNum + 1, length, salt, iterations, newOutput, onError, onSuccess);
                        }
                    });
                });                
            }
          
            _pbkdf2.importKeyHMAC(password, onError, function(key) {
                deriveLoop(key, 1, bitLength / 8, salt, iterations, new Uint8Array(), onError, function(derived) {
                    onSuccess({salt: salt.buffer, iterations: util.uint32toBuffer(iterations), derived: derived})
                });
            });
        }
        
        
         
    }

    
    /**
     * Simple Crypto Javascript library built on WebCrypto and IndexedDB
     * @module simpleCrypto
     */
    var simpleCrypto = {

        /**
         * Secure CryptoKey storage
         * @class Key Storage
         */
        storage: {
             /**
             * Get key from secure storage
             * 
             * @method storage.get
             * @param {String} keyId - Key Id
             * @param {function} onError - called with error details if get fails
             * @param {function} onSuccess - called with CryptoKey if get succeeds
             */
            get: function(keyId, onError, onSuccess) {
                dbUtil.get(keyId, onError, onSuccess);    
            },
            /**
             * Put key in secure storage
             * 
             * @method storage.put
             * @param {String} keyId - Key Id
             * @param {CryptoKey} key - key to be stored
             * @param {function} onError - called with error details if put fails
             * @param {function} onSuccess - called if put succeeds
             */
            put: function(keyId, key, onError, onSuccess) {
                dbUtil.put(keyId, key, onError, onSuccess);    
            },
            
            /**
             * Delete key from secure storage
             * 
             * @method storage.delete
             * @param {String} keyId - Key Id
             * @param {function} onError - called with error details if delete fails
             * @param {function} onSuccess - called if delete succeeds
             */
            delete: function(keyId, onError, onSuccess) {
                dbUtil.delete(keyId, onError, onSuccess);
            }
        },
        
        /**
         * Asymmetric Encryption
         * @class Encryption Asymmetric
         */
        asym : {
            /**
             * Generate RSA encryption and signature keys
             * 
             * @method asym.generateKeys
             * @param {function} onError - called with error details if generate fails
             * @param {function} onSuccess - called with {encrypt: ... , sign: ...} if generate succeeds
             */
            generateKeys: function(onError, onSuccess) {
                simpleCrypto.asym.generateEncryptKey(onError, function(encryptKey) {
                    simpleCrypto.asym.generateSignKey(onError, function(signKey) {
                        onSuccess({encrypt: encryptKey, sign: signKey});    
                    }); 
                });  
            },
            
            /**
             * Generate RSA encryption keys. Private CryptoKey is not exportable, and can be stored safely.
             * 
             * @method asym.generateEncryptKey
             * @param {function} onError - called with error details if generate fails
             * @param {function} onSuccess - called with {privateKey: CryptoKey, publicKey: CryptoKey, privateJwk: JWK, publicJwk: JWK} 
             */
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


            /**
             * Generate RSA signature keys. Private CryptoKey is not exportable, and can be stored safely.
             * 
             * @method asym.generateSignKey
             * @param {function} onError - called with error details if generate fails
             * @param {function} onSuccess - called with {privateKey: CryptoKey, publicKey: CryptoKey, privateJwk: JWK, publicJwk: JWK} 
             */
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
            
            

            /**
             * Decrypt. For large payloads, keys are RSA decrypted and content is AES decrypted. Otherwise, content is RSA decrypted.
             * 
             * @method asym.decrypt
             * @param {CryptoKey} decryptKey - RSA encryption private key
             * @param {Object} 
             * @param {function} onError - called with error details if decrypt fails
             * @param {function} onSuccess - called with decrypted ArrayBuffer
             */
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

            /**
             * Verify and Decrypt. For large payloads, AES keys are RSA decrypted and content is AES decrypted. Otherwise, content is RSA decrypted.
             * The order of operations is: verify encrypted content/keys, decrypt, verify decrypted content/keys, AES decrypt (if required). 
             * 
             * @method asym.verifyAndDecrypt
             * @param {CryptoKey} decryptKey - RSA encryption private key
             * @param {CryptoKey} decryptKey - RSA signature public key
             * @param {Object} dict - decoded encrypted object {rsaEncrypted:, signatureOfEncrypted:, signatureOfData:, aesEncrypted?:, hmac?: } 
             * @param {function} onError - called with error details if decrypt fails
             * @param {function} onSuccess - called with decrypted ArrayBuffer
             */
            verifyAndDecrypt: function (decryptKey, verifyKey, dict, onError, onSuccess) {
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
            
            /**
             * Encrypt. For large payloads, the content is AES encrypted and keys are RSA encrypted. Otherwise, the content is RSA encrypted. 
             * "Large" trashhold is defined in config.
             * 
             * @method asym.encrypt
             * @param {CryptoKey} encryptKey - RSA encryption public key
             * @param {Uint8Array | ArrayBuffer} data - Data to encrypt 
             * @param {function} onError - called with error details if encryption fails
             * @param {function} onSuccess - called with {rsaEncrypted: , aesEncrypted?: , hmacEncrypted?:}
             */
            encrypt: function(encryptKey, data, onError, onSuccess) {
                var rawData = {};
                this._encrypt(encryptKey, data, rawData, onError, onSuccess);
            },
            
            /**
             * Encrypt and Sign. For large payloads, the content is AES encrypted and keys are RSA encrypted. Otherwise, the content is RSA encrypted.
             * "Large" trashhold is defined in config.
             * The order of operations is: AES (encrypt if required), encrypt content/keys, sign content/keys, sign encrypted content/keys. 
             * 
             * @method asym.encryptAndSign
             * @param {CryptoKey} decryptKey - RSA encryption private key
             * @param {CryptoKey} decryptKey - RSA signature public key
             * @param {Object} dict - decoded encrypted object {rsaEncrypted:, signatureOfEncrypted:, signatureOfData:, aesEncrypted?:, hmac?: } 
             * @param {function} onError - called with error details if decrypt fails
             * @param {function} onSuccess - called with decrypted ArrayBuffer
             */
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


        /**
         * Symmetric Encryption
         * @class Encryption Symmetric
         */
        sym: {
            
            /** Generate random AES and HMAC keys
             *
             * @method sym.generateKeys
             * @param {function} onError - called with error details if the generation fails
             * @param {function} onSuccess - called with {aesKey: raw key, hmacKey: raw key, aesKeyObj: CryptoKey, hmacKeyObj: CryptoKey}
             */
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
            
            /** Convert raw AES and HMAC keys into WebCrypto CryptoKey objects
             *
             * @method sym.importKeys
             * @param {Object} keys - {aesKey: raw key, hmacKey: raw key}. After import CryptoKeys aesKeyObj and hmacKeyObj are added to keys object.
             * @param {function} onError - called with error details if the import fails
             * @param {function} onSuccess - called without arguments once import completes
             */
            importKeys: function(keys, onError, onSuccess) {
                
                // keys already has cached imported object
                if (("aesKeyObj" in keys) && ("hmacKeyObj" in keys)) {
                    onSuccess(keys);
                    return;
                }
                
                if (!keys || !("aesKey" in keys) || !("hmacKey" in keys)) {    
                    onError("Missing keys");
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
            
            /** Generate random AES and HMAC keys and encrypt data. This utility function combines generateKeys and encrypt
             * 
             * @method sym.genKeysAndEncrypt
             * @param {Uint8Array | ArrayBuffer} data - Data to encrypt
             * @param {function} onError - called with error details if key generation or encryption fail
             * @param {function} onSuccess - called with {keys: [see generateKeys output], data: [see encrypt output]) 
             */
            genKeysAndEncrypt: function(data, onError, onSuccess) {
                simpleCrypto.sym.generateKeys(onError, function(keys) {
                    simpleCrypto.sym.encrypt(keys, data, onError, function(encrypted){
                        onSuccess({ keys: keys, data: encrypted });
                    });
                });
            },
            
            /** Generate random AES and HMAC keys and encrypt data. This utility function combines generateKeys and encrypt
             *
             * @method sym.encrypt
             * @param {Object} keys - AES and HMAC keys. Also optional IV (otherwise random is generated)
             * @param {Uint8Array | ArrayBuffer} data - Data to encrypt
             * @param {function} onError - called with error details if key generation or encryption fail
             * @param {function} onSuccess - called with {aesEncrypted: ArrayBuffer, hmac: {ArrayBuffer}
             */
            encrypt: function (keys, data, onError, onSuccess) {

                simpleCrypto.sym.importKeys(keys, onError, function() {
                    var iv;
                    if ("iv" in keys) {
                        iv = keys.iv; 
                    }
                    else {
                        iv = window.crypto.getRandomValues(new Uint8Array(config.aesIvLength));
                    }
                    _sym.encrypt(keys.aesKeyObj, iv, data, onError.bind(null, "Could not AES Encrypt"), function(aesEncrypted){
                        _sym.signHMAC(keys.hmacKeyObj, aesEncrypted, onError.bind(null, "Could not HMAC sign"), function(hmac) {
                            var encrypted = { aesEncrypted: aesEncrypted, hmac: hmac };
                            onSuccess(encrypted);                           
                        });  
                    });
                });
            },
            
            encryptWithPassword: function(password, data, onError, onSuccess) {
                simpleCrypto.pbkdf2.derive(password, 288, {}, onError.bind(null, "PBKDF2 error"), function(pbkdf2) {
                    var keys = new Uint8Array(pbkdf2.derived);
                    var aesKeyLenght = config.aesLength / 8;                        
                    var aesKey = keys.subarray(0, aesKeyLenght);
                    var hmacKey = keys.subarray(aesKeyLenght);
                    console.log(aesKey, hmacKey);
                    simpleCrypto.sym.encrypt({aesKey: aesKey, hmacKey: hmacKey}, data, onError, function(encrypted){
                       encrypted.pbkdf2_salt = pbkdf2.salt;
                       encrypted.pbkdf2_iter = pbkdf2.iterations;
                       onSuccess(encrypted); 
                    });
                });    
            },
            
            decryptWithPassword: function(password, encrypted, onError, onSuccess) {
                simpleCrypto.pbkdf2.derive(password, 288, {salt: encrypted.pbkdf2_salt, iterations: encrypted.pbkdf2_iter}, 
                    onError.bind(null, "PBKDF2 error"), function(pbkdf2) {
                        var keys = new Uint8Array(pbkdf2.derived);
                        var aesKeyLenght = config.aesLength / 8;                        
                        var aesKey = keys.subarray(0, aesKeyLenght);
                        var hmacKey = keys.subarray(aesKeyLenght);
                        simpleCrypto.sym.decrypt({aesKey: aesKey, hmacKey: hmacKey}, encrypted, onError, function(decrypted) {
                            onSuccess(decrypted);
                            
                        });
                    }
                );
            },

            /** Decrypt
             *  
             * @method sym.decrypt
             * @param {Object} keys - AES and HMAC keys. Also optional IV (otherwise random is generated)
             * @param {Uint8Array | ArrayBuffer} data - Data to encrypt
             * @param {function} onError - called with error details if key generation or encryption fail
             * @param {function} onSuccess - called with {aesEncrypted: ArrayBuffer, hmac: {ArrayBuffer}
             */
            decrypt: function (keys, encrypted, onError, onSuccess) {
                simpleCrypto.sym.importKeys(keys, onError, function(){
                    _sym.verifyHMAC(keys.hmacKeyObj, encrypted.hmac, encrypted.aesEncrypted, onError.bind(null, "Could not verify HMAC"), function(){
                        _sym.decryptAES(keys.aesKeyObj, encrypted.aesEncrypted, onError.bind(null, "Could not AES decrypt"), function(decrypted) {
                            onSuccess(decrypted);
                        });
                    });    
                });
            }
            
        },
        
        /** 
         * Password-Based Key Derivation Function 2
         * @class pbkdf2
         */
        pbkdf2 : {
            
            /** Derive a byte array from a password 
             * 
             * @method derive
             * @param {String} password
             * @param {int} bitLength - request lenght, in bits
             * @param {Object} options - number of iterations and salt, if required. Autogenerated otherwise
             * @param {function} onError - called with error details if derive fails
             * @param {function} onSuccess - called with {salt: ArrayBuffer, interations: int, array: derived data}
             */
            derive: function(password, bitLength, options, onError, onSuccess) {
                
                try {
                    _pbkdf2.passwordToKey(password, 
                        // lot of browsers/platforms don't support PBKDF2. Try compat method.
                        function(error) {
                            _pbkdf2.compatDerive(password, bitLength, options, onError.bind(null, "Compat: could not derive bits"), onSuccess);
                        },
                        // PBKDF2 works, derive bits.
                        function(key) {
                            _pbkdf2.deriveBits(key, bitLength, options, onError.bind(null, "Could not derive bits"), onSuccess);
                        }
                    );
                } catch (e) {
                    // IE will not return onError, but instead throw an exception
                    _pbkdf2.compatDerive(password, bitLength, options, onError.bind(null, "Compat: could not derive bits"), onSuccess);
                }
            }
        },
        /**
         * Encoding/Decoding for encrypted data transport
         * @class Packaging
         */
        pack : {
                
            VERSION: 1,
            
            LABEL_TO_INDEX: {
                        // symmetric
                        aesEncrypted : 0, hmac: 1,
                        // asymmetric
                        rsaEncrypted: 10,
                        signatureOfData: 20, signatureOfEncrypted: 21,
                        pbkdf2_iter: 30, pbkdf2_salt: 31
            },
            INDEX_TO_LABEL: {
                        0: "aesEncrypted", 1: "hmac",
                        10: "rsaEncrypted",
                        20: "signatureOfData", 21: "signatureOfEncrypted",
                        30: "pbkdf2_iter", 31: "pbkdf2_salt"
            },
        
         
            /**
             * Encode encrypted data
             * 
             * @method pack.encode
             * @param {Object} dict - Keys depend on type of encryption, all values are ArrayBuffers (as returned by WebCrypto)
             * @return {ArrayBuffer} - Encoded data
             */
            encode: function(dict) {
        
                var size = 1;
                var numItems = 0;
                for (var label in dict) {
                    if (!(label in this.LABEL_TO_INDEX)) {
                        throw "Unsupported key: " + label;
                    }
                    if (!(dict[label] instanceof ArrayBuffer)) {
                        throw "Value is not ArrayBuffer: " + label;
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
        
        
            /**
             * Decode encrypted data. Decoding should be a zero copy operation, since all returned Uint8Arrays point to the original buffer
             * 
             * @method pack.decode
             * @param {ArrayBuffer} buffer - Encoded data
             * @return {Object} - Keys depend on type of encryption, all values are Uint8Arrays
             */
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
    simpleCrypto.test = _pbkdf2;
    simpleCrypto.s2b = util.stringToBytes;
    return simpleCrypto;
}));