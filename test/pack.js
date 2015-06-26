describe('pack', function() {
    var emptyBuffer = new Uint8Array(32).buffer;
    var gEnc;
    it('encode', function(done) {        
        var dict = { aesEncrypted: emptyBuffer, hmac: emptyBuffer, 
                     rsaEncrypted: emptyBuffer, 
                     signatureOfData: emptyBuffer, signatureOfEncrypted: emptyBuffer };
        gEnc = simpleCrypto.encoding.encode(dict);
        done();
    });
    it('decode', function(done) {
        var dict = simpleCrypto.encoding.decode(gEnc);
        expect(new Uint8Array(emptyBuffer)).toEqual(new Uint8Array(dict.aesEncrypted));
        expect(new Uint8Array(emptyBuffer)).toEqual(new Uint8Array(dict.hmac));
        expect(new Uint8Array(emptyBuffer)).toEqual(new Uint8Array(dict.rsaEncrypted));
        expect(new Uint8Array(emptyBuffer)).toEqual(new Uint8Array(dict.signatureOfData));
        expect(new Uint8Array(emptyBuffer)).toEqual(new Uint8Array(dict.signatureOfEncrypted));
        done();
    });

});