
function logError(callback, error) {
    console.log(arguments);
    if (arguments.length > 2 && arguments[2] instanceof DOMException) {
        console.log(arguments[2].message);
    }
    throw "Error";
}

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
    var hmacKey = new Uint8Array(20);


    beforeEach(function (done) {
        var keys = {aesKey: aesKey, hmacKey: hmacKey};
        simpleCrypto.sym.encrypt(keys, testArray, logError.bind(null, done), function(encrypted) {
           simpleCrypto.sym.decrypt(keys, encrypted, logError.bind(null, done), function(decrypted) {
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

describe('symmetricWithPassword', function() {
    var testArray = new Uint8Array(Array.apply(null, new Array(100)).map(function(){return 5}));
    var password = "simplecrypt0";
    var gEncrypted, gPacked, gUnpacked;
    
    it('encrypt', function(done) {
        simpleCrypto.sym.encryptWithPassword(password, testArray, logError.bind(null, done), function(encrypted){
            expect(encrypted.aesEncrypted).not.toBeUndefined();
            gEncrypted = encrypted;
            done();
        });
    });
    it('pack', function() {
        try {
            gPacked = simpleCrypto.pack.encode(gEncrypted); 
        }
        catch (e) {
            console.log("Error", JSON.stringify(gEncrypted), e);
        }
        expect(gPacked).not.toBeUndefined();
    });
    it('unpack', function() {
        gUnpacked = simpleCrypto.pack.decode(gPacked);
    });
    
    it('decrypt', function(done) {
        simpleCrypto.sym.decryptWithPassword(password, gEncrypted, logError.bind(null, done), function(decrypted){
            expect(decrypted).not.toBeUndefined();
            expect(new Uint8Array(decrypted)).toEqual(testArray);
            done();
        });
    });
});
