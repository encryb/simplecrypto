
function logError(callback, error) {
    console.log(arguments);
    if (arguments.length > 2 && arguments[2] instanceof DOMException) {
        console.log(arguments[2].message);
    }
    throw "Error";
}

beforeEach(function() {
  jasmine.DEFAULT_TIMEOUT_INTERVAL = 15000;
});

describe('asymmetric', function() {
    var testArray = new Uint8Array(Array.apply(null, new Array(100)).map(function(){return 5}));
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
            expect(new Uint8Array(decrypted)).toEqual(testArray);
            done();
        });
    });
});


describe('asymmetricLarge', function() {
    var testArray = new Uint8Array(Array.apply(null, new Array(10000)).map(function(){return 5}));
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
            expect(new Uint8Array(decrypted)).toEqual(testArray);
            done();
        });
    });
});


describe('asymmetricWithSign', function() {
    var testArray = new Uint8Array(Array.apply(null, new Array(100)).map(function(){return 5}));
    var gKeys, gEncrypted;
    var gPacked, gUnpacked;
    
    
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
    it('pack', function() {
        gPacked = simpleCrypto.encoding.encode(gEncrypted);
        expect(gPacked).not.toBeUndefined();
    });
    it('unpack', function() {
        gUnpacked = simpleCrypto.encoding.decode(gPacked);
       // console.log("UNPACKED", new Uint8Array(gUnpacked.cipherdata));
       // console.log("Encrypted", new Uint8Array(gEncrypted.cipherdata));
    });
    it('verify and decrypt', function(done) {
        simpleCrypto.asym.verifyAndDecrypt(gKeys.encrypt.privateKey, gKeys.sign.publicKey, gUnpacked, logError.bind(null, done), function(decrypted){
            expect(decrypted).not.toBeUndefined();
            expect(new Uint8Array(decrypted)).toEqual(testArray);
            done();
        });
    });
});


describe('asymmetricWithSignLarge', function() {
    var testArray = new Uint8Array(Array.apply(null, new Array(10000)).map(function(){return 5}));
    var gKeys, gEncrypted;
    var gPacked, gUnpacked;
    
    
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
    it('pack', function() {
        gPacked = simpleCrypto.encoding.encode(gEncrypted);
        expect(gPacked).not.toBeUndefined();
    });
    it('unpack', function() {
        gUnpacked = simpleCrypto.encoding.decode(gPacked);
       // console.log("UNPACKED", new Uint8Array(gUnpacked.cipherdata));
       // console.log("Encrypted", new Uint8Array(gEncrypted.cipherdata));
    });
    it('verify and decrypt', function(done) {
        simpleCrypto.asym.verifyAndDecrypt(gKeys.encrypt.privateKey, gKeys.sign.publicKey, gUnpacked, logError.bind(null, done), function(decrypted){
            expect(decrypted).not.toBeUndefined();
            expect(new Uint8Array(decrypted)).toEqual(testArray);
            done();
        });
    });
});



