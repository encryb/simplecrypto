describe('pbkdf2', function() {
	
	it('rfc6070test1', function(done) {
		var password = "password";
		var salt = new Uint8Array([115, 97, 108, 116]);
		var iterations = 1;
		var bitLength = 160;
		var correct = new Uint8Array([12, 96, 200, 15, 150, 31, 14, 113, 243, 169, 181, 36, 175, 96, 18, 6, 47, 224, 55, 166]);
		
		
		simpleCrypto.pbkdf2.derive(password, bitLength, {iterations: iterations, salt: salt}, 
			function() {
				console.error(arguments);
			}, 
			function(result) {
		        expect(new Uint8Array(result.derived)).toEqual(correct);
				done();
			}
		);
	});
	
	
	it('rfc6070test2', function(done) {
		var password = "password";
		var salt = new Uint8Array([115, 97, 108, 116]);
		var iterations = 2;
		var bitLength = 160;
		var correct = new Uint8Array([234, 108, 1, 77, 199, 45, 111, 140, 205, 30, 217, 42, 206, 29, 65, 240, 216, 222, 137, 87]);
		
		
		simpleCrypto.pbkdf2.derive(password, bitLength, {iterations: iterations, salt: salt}, 
			function() {
				console.error(arguments);
			}, 
			function(result) {
		        expect(new Uint8Array(result.derived)).toEqual(correct);
				done();
			}
		);
	});
	
	
	it('rfc6070test4', function(done) {
		var password = "passwordPASSWORDpassword";
		// saltSALTsaltSALTsaltSALTsaltSALTsalt
		var salt = new Uint8Array([115, 97, 108, 116, 83, 65, 76, 84, 115, 97, 108, 116, 83, 65, 76, 84, 115, 97, 108, 116, 83, 65, 76, 84, 115, 97, 108, 116, 83, 65, 76, 84, 115, 97, 108, 116]);
		var iterations = 4096;
		var bitLength = 200;
		var correct = new Uint8Array([61, 46, 236, 79, 228, 28, 132, 155, 128, 200, 216, 54, 98, 192, 228, 74, 139, 41, 26, 150, 76, 242, 240, 112, 56]);
		
		simpleCrypto.pbkdf2.derive(password, bitLength, {iterations: iterations, salt: salt}, 
			function() {
				console.error(arguments);
			}, 
			function(result) {
		        expect(new Uint8Array(result.derived)).toEqual(correct);
				done();
			}
		);
	});
	
});
	