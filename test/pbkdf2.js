describe('pbkdf2', function() {
	var password = "Hello World";
	var salt = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);
	var iterations = 100000;
	it('derive', function(done) {
		simpleCrypto.pbkdf2.derive(password, 32, {iterations: iterations, salt: salt}, 
			function() {
				console.error(arguments);
			}, 
			function(result) {
				console.log("RESULT", new Uint8Array(result.array));
		        expect(new Uint8Array(result.array)).toEqual(new Uint8Array([127, 186, 152, 220]));
			}
		);
	});
});
	