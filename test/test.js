function logError(callback, error) {
    console.log("EEEEEEEEEEERRRRRRRRRRRRRRROOOOOOOOOOOOOOOOOOOORRRRRRRRRRRRRRRRRRRRRR");
    console.error(error.message);
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



describe('symmetric', function() {

    var testArray = new Uint8Array([1,2,3]);
    var wrongArray = new Uint8Array([2,3,4]);
    var result;

    beforeEach(function (done) {
        simpleCrypto.sym.genKeysAndEncrypt(testArray, logError.bind(null, done), function(encrypted) {
           simpleCrypto.sym.decrypt(encrypted.data, encrypted.keys, logError.bind(null, done), function(decrypted) {
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
        simpleCrypto.sym.encrypt(testArray, {aesKey: aesKey, hmacKey: hmacKey}, logError.bind(null, done), function(encrypted) {
           simpleCrypto.sym.decrypt(encrypted.data, encrypted.keys, logError.bind(null, done), function(decrypted) {
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
    
    beforeEach(function (done) {
        simpleCrypto.asym.generateKeys(logError.bind(null, done), function(keys){
            simpleCrypto.asym.encryptAndSign(keys.encrypt.publicKey, keys.sign.privateKey, testArray, logError.bind(null, done), function(encrypted) {
                simpleCrypto.asym.verifyAndDecrypt(keys.encrypt.privateKey, keys.sign.publicKey, encrypted, logError.bind(null, done), function(decrypted){
                    result = decrypted;
                    done();
                });
            });
        });
    });
    it('encrypt and decrypt', function() {
        expect(result).not.toBeUndefined();
        expect(new Uint8Array(result)).toEqual(testArray);
        expect(new Uint8Array(result)).not.toEqual(wrongArray);
    });
});
