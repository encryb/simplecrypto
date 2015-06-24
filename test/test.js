
function logError(callback, error) {
    console.log(arguments);
    callback();
}

function isSame(arr1, arr2) {
    return (
        arr1.length == arr2.length &&    
        arr1.every(function(element, index) {
            return element === arr2[index]; 
        })
    )
}

beforeEach(function() {
  jasmine.DEFAULT_TIMEOUT_INTERVAL = 15000;
});


describe('symmetric', function() {

    var testArray = new Uint8Array([1,2,3]);
    var wrongArray = new Uint8Array([2,3,4]);
    var result;

    beforeEach(function (done) {
        simpleCrypto.sym.genKeysAndEncrypt(testArray, logError.bind(null, done), function(encrypted) {
           simpleCrypto.sym.decrypt(encrypted.keys, encrypted.data, logError.bind(null, done), function(decrypted) {
              result = decrypted;
              done(); 
           });
        });
    });
    it('encrypt and decrypt', function() {
        expect(result).not.toBeUndefined();
        expect(new Uint8Array(result)).toEqual(testArray);
        expect(new Uint8Array(result)).not.toEqual(wrongArray);
    });
});



describe('symmetricWithKeys', function() {

    var testArray = new Uint8Array([1,2,3]);
    var wrongArray = new Uint8Array([2,3,4]);
    var result;

    var aesKey = new Uint8Array(16);
    var hmacKey = new Uint8Array(32);


    beforeEach(function (done) {
        simpleCrypto.sym.encrypt({aesKey: aesKey, hmacKey: hmacKey}, testArray, logError.bind(null, done), function(encrypted) {
           simpleCrypto.sym.decrypt(encrypted.keys, encrypted.data, logError.bind(null, done), function(decrypted) {
              result = decrypted;
              done(); 
           });
        });
    });
    it('encrypt and decrypt', function() {
        expect(result).not.toBeUndefined();
        expect(new Uint8Array(result)).toEqual(testArray);
        expect(new Uint8Array(result)).not.toEqual(wrongArray);
    });
});

describe('asymmetric', function() {
    var testArray = new Uint8Array([1,2,3]);
    var wrongArray = new Uint8Array([2,3,4]);
    var result;
    var gKeys, gEncrypted, gPrivateKey;
    
    it('generate keys', function(done) {
        simpleCrypto.asym.generateEncryptKey(logError.bind(null, done), function(keys){
            expect(keys).not.toBeUndefined();
            gKeys = keys;
            done();
        });
    });
    it('store keys', function(done) {
        simpleCrypto.db.put("privateKey", gKeys.privateKey, logError.bind(null, done), function(){
            done();
        });
    });
    it('load keys', function(done) {
        simpleCrypto.db.get("privateKey", logError.bind(null, done), function(privateKey){
            gPrivateKey = privateKey;
            done();
        });
    });
    
    it('encrypt', function(done) {
        simpleCrypto.asym.encrypt(gKeys.publicKey, testArray, logError.bind(null, done), function(encrypted) {
            expect(encrypted).not.toBeUndefined();
            gEncrypted = encrypted;
            done();
        });
    });
    it('decrypt', function(done) {
        simpleCrypto.asym.decrypt(gPrivateKey, gEncrypted, logError.bind(null, done), function(decrypted){
            expect(decrypted).not.toBeUndefined();
            console.log(new Uint8Array(decrypted));
            expect(new Uint8Array(decrypted)).toEqual(testArray);
            done();
        });
    });
});


describe('asymmetricWithSign', function() {
    var testArray = new Uint8Array([1,2,3]);
    var wrongArray = new Uint8Array([2,3,4]);
    var result;
    var gKeys, gEncrypted;
    
    it('generate keys', function(done) {
        simpleCrypto.asym.generateKeys(logError.bind(null, done), function(keys){
            expect(keys).not.toBeUndefined();
            gKeys = keys;
            done();
        });
    });
    it('encrypt and sign', function(done) {
        simpleCrypto.asym.encryptAndSign(gKeys.encrypt.publicKey, gKeys.sign.privateKey, testArray, logError.bind(null, done), function(encrypted) {
            expect(encrypted).not.toBeUndefined();
            gEncrypted = encrypted;
            done();
        });
    });
    it('verify and decrypt', function(done) {
        simpleCrypto.asym.verifyAndDecrypt(gKeys.encrypt.privateKey, gKeys.sign.publicKey, gEncrypted, logError.bind(null, done), function(decrypted){
            expect(decrypted).not.toBeUndefined();
            console.log(new Uint8Array(decrypted));
            expect(new Uint8Array(decrypted)).toEqual(testArray);
            done();
        });
    });
});


describe('pack', function() {
    var emptyBuffer = new Uint8Array(32).buffer;
    var gEnc;
    it('encode', function(done) {        
        var dict = { cipherdata: emptyBuffer, hmac: emptyBuffer, encryptedKeys: emptyBuffer, 
            keysSignature: emptyBuffer, encryptedKeysSignature: emptyBuffer };
        gEnc = simpleCrypto.encoding.encode(dict);
        done();
    });
    it('decode', function(done) {
        var dict = simpleCrypto.encoding.decode(gEnc);
        expect(new Uint8Array(emptyBuffer)).toEqual(new Uint8Array(dict.cipherdata));
        expect(new Uint8Array(emptyBuffer)).toEqual(new Uint8Array(dict.hmac));
        expect(new Uint8Array(emptyBuffer)).toEqual(new Uint8Array(dict.encryptedKeys));
        expect(new Uint8Array(emptyBuffer)).toEqual(new Uint8Array(dict.keysSignature));
        expect(new Uint8Array(emptyBuffer)).toEqual(new Uint8Array(dict.encryptedKeysSignature));
        done();
    });

});