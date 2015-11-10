function logError(callback, error) {
    console.log(JSON.stringify(arguments[1]));
    if (arguments.length > 2 && arguments[2] instanceof DOMException) {
        console.log(arguments[2].message);
    }
    throw "Error";
}

beforeEach(function() {
  jasmine.DEFAULT_TIMEOUT_INTERVAL = 15000;
});

describe('asymmetric', function() {
    var gPrivateKeys, gPublicKey, gDecoded;

    var source = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16];
    var encoded = [1,10,0,0,1,0,5,233,105,240,249,173,114,207,245,91,45,155,186,187,18,110,12,37,100,103,232,210,40,246,42,197,226,29,51,70,21,43,144,43,96,3,247,27,238,95,152,84,191,242,62,179,62,131,60,209,55,227,96,145,92,24,221,95,120,68,153,40,67,48,108,20,122,130,16,237,16,245,152,167,92,90,202,125,162,62,186,119,55,160,106,147,224,119,18,27,248,173,214,72,88,245,39,81,170,213,151,28,111,182,66,109,21,189,237,5,84,235,58,248,248,63,10,107,124,121,215,139,69,209,76,8,177,4,182,48,155,130,155,119,83,95,168,26,247,201,118,28,49,197,201,237,156,254,252,43,111,86,66,215,81,204,14,50,187,245,129,36,152,16,153,229,34,4,70,192,240,199,176,34,141,72,143,64,213,227,4,67,69,84,229,171,189,46,214,16,142,66,21,72,89,26,245,189,147,28,96,147,150,7,22,241,23,0,177,213,141,248,231,94,134,176,192,79,36,45,189,133,215,216,112,98,19,0,199,126,74,130,215,87,106,156,11,24,171,246,60,169,204,90,87,93,149,131,10,8,52,175,148,107,90,89];
    
    // "extractable -> ext"
    // remove key_ops
    it('import private key', function(done) {
        var privateKey = JSON.parse('{"alg":"RSA-OAEP","d":"SYDKW_-WSonpAoXFUuawoJJBDyyhV7Np8uC5UtgyorKn9h8mnE8Q_0mBet2WygnkQ3LiYn-yTV3-o4tvCdFL-LzJE4sx9wkJgWI5Qt9lpWWcat65bkNn2oG-BFeXhRuk8gsg-bt7UN8eYA4KT8NHLXe5XNIgPce6xLByPDnRvZS-FL-BDo3kTIxwgiNycMkvYgCCdRsFrpk4VM6QvZ-7wR4-8oBoU6s21LkI8FhBEHJvGNj-ee4CWULXkAC3xpQFHhh018Tgaxoh5brkWEsY3jqpnNIbWAUofdf9lgHTXic40S09Ezduo2kB3bGKN7y56zB7eVVzRqwp8oBrjEbbqQ","dp":"AzolxyCM0mN1eRT-BbILUPh9_vqDvrEgKHCM8ret_ZZ7SZ4QS3tvrIpk-GBdaq66fC44EmjeKS4myahue43IvFiOGjqZ6_pzF5E-6pfyki9wJASPBM3PYRtmFr54fYv781xVRgxjIYqZbE7gXR8L_OhUxv26rEznE2KLi9Mnvqs","dq":"oVv8pgcdrZ62YadzlyfUGjlvcBvGg58FpifaFo3nJxo0ziZLQJbycjc510N9rW_pA76mgg90H6PPj_uCjtUi_YW3iFsKNz8ZW3tp0Jw2G8TNQ3iwlTfTib1lOF5P4FK66zUqatAuI_p2-QAR9bZGmd4Ex50h9nli8Sb8kYZyeh0","e":"AQAB","ext":true,"key_ops":["decrypt"],"kty":"RSA","n":"nUpPP8LmFqM6og1oCmYKqOhTEOp0fheV_qbHVvZMoBE1SURMZVuB7xGtWaZfdKVbxnvLSJbm2Tvd13W7VWoFzSaVSvtQnYHI86StCeK_hqflQWjfl6eDd90H26s9T2LNgnMk50c1wDETxTCvc68TruA-OnD0WM4I9tlKDIFhAi74mLxFkBU0-mtR34Ple9JbbgK_OpBAKffkFI8oBtXy3jpe03BYwG-vAn4en5g1KLpRKVjhdj290MxHO_drrfamGbPg4pGQOJaJUAysTU-w64tR7TnrZgLR9v5ghuBurWRR-jI1q-hfcRqRSumXsDfWzkRPR6w0tuJEgAp4zRoV4Q","p":"zlaqputB65cRXkY1HryRnIyat3LRmNGCA6xttbq-oXXaj7KNv37qQ_Nj2F9a7E43LGH3qlGQHww65RTDzh2LJYk6Y5Qkm_DITwHefhfEl1q-LaFaALTegxEIRxIKfn7AJgimbs6X1XlfYjqcWMQV95aGMxOlmH64ZE6n7bF4Fqs","q":"wyWVytyr8UgPzJdisvwTUmfEtcydLZN7yXP1mXLjobaHsoBVJGoZYipnacxXa2MAMmBdIAxZhve_d7IB4b7MAADa9peeWpO3cyFjAhj-dbhK8dioZT_OubM3_ThSdTB5rv2_4lhFGuu_WkX81XSoq61qf7FI5Cv_aEU51cfW9aM","qi":"XbzVUJwCM3P3fJjpd6gep3uUnhIuUWWdWlTT6WhJ_twNZ-hSziZwHX6vM7KkDoHNgylyBQtfwY1xdLS2UFH1JF2KSEUybgHRz8xRP8FS12QTD2XrY84Y8y_a68llYwsA40mgmDVEq_tmK_QP8gxx7Cqvrym1AFeWD39PsNeqUXM"}');
        
        simpleCrypto.internal.asym.importEncryptKey(privateKey, ["decrypt"], logError.bind(null, done), function(privateKey) {
            gPrivateKey = privateKey;
            done();            
        });
    });
    it('import public key', function(done){
        var publicKey = JSON.parse('{"alg":"RSA-OAEP","e":"AQAB","ext":true,"key_ops":["encrypt"],"kty":"RSA","n":"nUpPP8LmFqM6og1oCmYKqOhTEOp0fheV_qbHVvZMoBE1SURMZVuB7xGtWaZfdKVbxnvLSJbm2Tvd13W7VWoFzSaVSvtQnYHI86StCeK_hqflQWjfl6eDd90H26s9T2LNgnMk50c1wDETxTCvc68TruA-OnD0WM4I9tlKDIFhAi74mLxFkBU0-mtR34Ple9JbbgK_OpBAKffkFI8oBtXy3jpe03BYwG-vAn4en5g1KLpRKVjhdj290MxHO_drrfamGbPg4pGQOJaJUAysTU-w64tR7TnrZgLR9v5ghuBurWRR-jI1q-hfcRqRSumXsDfWzkRPR6w0tuJEgAp4zRoV4Q"}');
        simpleCrypto.internal.asym.importEncryptKey(publicKey, ["encrypt"], logError.bind(null, done), function(publicKey) {
            gPublicKey = publicKey;
            done();            
        });
    });
    it ('decode', function() {
        gDecoded = simpleCrypto.pack.decode(new Uint8Array(encoded).buffer);
        
    });
    it('decrypt', function(done) {
       simpleCrypto.asym.decrypt(gPrivateKey, gDecoded, logError.bind(null, done), function(decrypted) {
           expect(new Uint8Array(decrypted)).toEqual(new Uint8Array(source));
           done();
       }) 
    });
});