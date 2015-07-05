# simplecrypto for javascript

## Purpose

Simple Javascript cryptography library wraps incompatible WebCrypto implementations, 
utilizes encryption algorithms that all WebCrypto implmentations support and provides 
a much simpler interface. 

## Supported Browsers

(Desktop and mobile versions)
Chrome 41+
Firefox 37+
Internet Explorer 11+
Safari 8.1+ (RSA signing is not available due to a [WebKit bug](https://bugs.webkit.org/show_bug.cgi?id=144938))

## Examples

### Common
```javascript
var data = new Uint9Array([5,4,3,2,1]);

var logError = function() {
    console.log(arguments);
}    
```

### Symmetric
```javascript
var aesKey = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6]);
var hmacKey = new Uint8Array([1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6]);

simpleCrypto.sym.encrypt(keys, data, logError, function(encrypted) {
    simpleCrypto.sym.decrypt(keys, encrypted, logError.bind(null, done), function(decrypted) {});
});
```

### Asymmetric
```javascript
simpleCrypto.asym.generateEncryptKey(logError, function(keys){
    simpleCrypto.asym.encrypt(key.publicKey, data, logError, function(encrypted) {
        simpleCrypto.asym.decrypt(key.privateKey, encrypted, logError.bind(null, done), function(decrypted){});
    });
});
    
```

Please see [Unit Tests](https://github.com/encryb/simplecrypto/tree/master/test) for more examples

## Documentation
[API](http://rawgit.com/encryb/simplecrypto/master/docs/modules/simpleCrypto.html)

## FAQ

Q: Why another Javascript Crypto library?
A: Simplecrypto is built on top of WebCrypto and IndexedDB. Performance advantage over other libraries is 
[significant](https://medium.com/@encryb/comparing-performance-of-javascript-cryptography-libraries-42fb138116f3). 
IndexedDB provides for safer storage of Javascript keys.

Q: Why AES-CBC-HMAC instead of AES-GCM?
A: WebKit does not support AES-GCM.

Q: Why is there no support for PBKDF2?
WebKit does not support PBKDF2. Support for other browsers is coming soon.

## License
Apache 2.0

