describe('symmetric', function() {

    var testArray = new Uint8Array([1,2,3]);
    var wrongArray = new Uint8Array([2,3,4]);
    var result;

    beforeEach(function (done) {
        simpleCrypto.sym.encrypt(testArray, done, function(encypted) {
           simpleCrypto.sym.decrypt(encypted, done, function(decrypted) {
              result = decrypted;
              done(); 
           });
        });
    });
    it('symmetric encrypt and decrypt', function() {
        expect(result).not.toBeUndefined();
        expect(new Uint8Array(result)).toEqual(testArray);
        expect(new Uint8Array(result)).not.toEqual(wrongArray);
    });
});
