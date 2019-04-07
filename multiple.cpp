/*
 *  multiple.cpp
 *  RSA
 *
 *  Created by Samuel Williams on 23/08/10.
 *  Copyright 2010 Orion Transfer Ltd. All rights reserved.
 *
 */

#include "Integer.h"
#include <iostream>
#include <ctime>
#include <sys/time.h>
#include <string>
#include <cassert>
#include <fstream>

typedef double TimeT;
typedef std::string StringT;
typedef std::vector<Integer> TextT;
	
TimeT systemTime () {
	struct timeval t;
	gettimeofday (&t, (struct timezone*)0);
	return ((TimeT)t.tv_sec) + ((TimeT)t.tv_usec / 1000000.0);
}

// Approximately 50 decimal digits
const int BITS_50D = 32 * 6;

struct RSAKeys {
	Integer n, e, d;
	
	Integer p, q;
};

RSAKeys generateKeyPair (std::size_t bits = 256) {	
	// Find two large primes using probabilistic method.
	Integer p, q;
//	std::cerr << "Generating p..." << std::endl;
	p.generatePrime(bits / Integer::DIGIT_BITS);

//	std::cerr << "Generating q..." << std::endl;	
	do {
		q.generatePrime(bits / Integer::DIGIT_BITS);
	} while (q == p);

	// Compute (e, n) and (d, n) keys.
	Integer n;
	n.setProduct(p, q);

	std::cerr << "p = " << p.toString() << " q = " << q.toString() << std::endl
	          << "n = " << n.toString() << std::endl;	
		
	Integer e = 0;
	
	// Generate public key - does this need to use Euclidean algorithm here??
//	std::cerr << "Generating e..." << std::endl;
	e.generatePrime(bits / Integer::DIGIT_BITS);

	std::cerr << "e = " << e.toString() << std::endl;

	Integer p1 = p, q1 = q;
	p1.subtract(1);
	q1.subtract(1);

	/*
	// Check encryption key	
	Integer gcd = e;
	gcd.calculateGreatestCommonDivisor(e, p1);
	assert(gcd == 1);
	gcd.calculateGreatestCommonDivisor(e, q1);
	assert(gcd == 1);
	*/
	
	// Generate private key
//	std::cerr << "Generating d..." << std::endl;
	Integer phi = 0;
	phi.setProduct(p1, q1);
	Integer d = 0;
	d.calculateInverse(e, phi);
	
	Integer ed;
	ed.setProduct(e, d);
	ed.modulus(phi);
	
	std::cerr //<< "phi = " << phi.toString() << std::endl
	          << "d = " << d.toString() << std::endl;
//			  << "ed = " << ed.toString() << std::endl;
	
	assert(ed == 1);
			  
//	std::cerr << "\tpublic = " << n.toString() << ", " << e.toString() << std::endl
//			  << "\tprivate = " << n.toString() << ", " << d.toString() << std::endl;
	
	RSAKeys keys;
	keys.p = p;
	keys.q = q;
	keys.n = n;
	keys.e = e;
	keys.d = d;
	
	return keys;
}

TextT transformMessage(Integer e, Integer n, TextT message) {
	TextT result;
	
	BarrettReduction br(n);
	Integer c;
	
	for (TextT::iterator i = message.begin(); i != message.end(); i++) {
		c = *i;
		
		// Ensure that c will be recoverable.
		assert(c < n);
		
		c.setPower(*i, e, br);
		
		result.push_back(c);
	}
	
	return result;
}

TimeT g_totalTime = 0;
TimeT g_totalBytes = 0;

TextT pack(StringT input, std::size_t s)
{
	const std::size_t PACK_BLOCKS = s;
	const std::size_t PACK_BYTES = sizeof(Integer::DigitT) * PACK_BLOCKS;

	TextT output;	
	input.resize(((input.size() + PACK_BYTES - 1)  / PACK_BYTES) * PACK_BYTES);
	
	for (std::size_t i = 0; i < input.size(); i += PACK_BYTES) {
		Integer j((Integer::DigitT*)&input[i], PACK_BLOCKS);
				
		output.push_back(j);
	}
	
	return output;
}

StringT unpack(const TextT & input, std::size_t s)
{
	const std::size_t PACK_BLOCKS = s;
	const std::size_t PACK_BYTES = sizeof(Integer::DigitT) * PACK_BLOCKS;

	StringT output;
	output.resize(input.size() * sizeof(Integer::DigitT) * PACK_BLOCKS);
	
	for (std::size_t i = 0; i < output.size(); i += PACK_BYTES) {
		input[i / PACK_BYTES].unpack((Integer::DigitT*)&output[i], PACK_BLOCKS);
	}
	
	return output;
}

TextT repack(const TextT & input, std::size_t s1, std::size_t s2)
{
	std::cout << "Packing from " << s1 << " to " << s2 << std::endl;
	
	StringT buffer = unpack(input, s1);
	return pack(buffer, s2);
}

void wait()
{
	std::cout << "Waiting..." << std::endl;
	std::string buffer;
	std::getline(std::cin, buffer);
}

void testEncryption (StringT input, std::size_t bits) {	
	TimeT start;
	TimeT packStart, packTotal = 0;
	
	start = systemTime();
	std::cerr << "Generating key A" << std::endl;
	RSAKeys keysA = generateKeyPair(bits);
	
	std::cerr << "Generating key B" << std::endl;
	RSAKeys keysB = generateKeyPair(bits);
	TimeT keyGenerationTime = systemTime() - start;
	
	std::cout << "Time for key generation: " << keyGenerationTime << "s" << std::endl;

	wait();

	packStart = systemTime();
	TextT cipherText = pack(input, keysA.n.size() - 1);
	packTotal += systemTime() - packStart;
	
	// Ea(Db(Eb(Da(M)))) = M 
	start = systemTime();
	// The output of this function can be up to size keysA.n
	cipherText = transformMessage(keysA.d, keysA.n, cipherText);

	packStart = systemTime();
	cipherText = repack(cipherText, keysA.n.size(), keysB.n.size() - 1);
	packTotal += systemTime() - packStart;
			
	cipherText = transformMessage(keysB.e, keysB.n, cipherText);
	TimeT encryptionTime = systemTime() - start;
	
	std::cout << "     Encrypted Text: " << cipherText << std::endl;
	std::cout << "Time for encryption: " << encryptionTime << "s" << std::endl; 

	wait();

	TextT decipherText = cipherText;
	
	start = systemTime();	
	decipherText = transformMessage(keysB.d, keysB.n, decipherText);

	packStart = systemTime();
	decipherText = repack(decipherText, keysB.n.size() - 1, keysA.n.size());
	packTotal += systemTime() - packStart;

	decipherText = transformMessage(keysA.e, keysA.n, decipherText);
	TimeT decryptionTime = systemTime() - start;
	
	// Unpack
	packStart = systemTime();
	StringT output = unpack(decipherText, keysA.n.size());
	packTotal += systemTime() - packStart;
	
	TimeT totalTime = encryptionTime + decryptionTime + keyGenerationTime;
	
	std::cout << "     Decrypted Text: " << output << std::endl;
	std::cout << "Time for decryption: " << decryptionTime << "s" << std::endl;
	std::cout << "         Total time: " << totalTime << std::endl;
	std::cout << "   Pack/Unpack time: " << packTotal << "s" << std::endl;

	// Data was encrypted/decrypted 4 times.
	TimeT bytes = input.size() * 4;
	
	std::cout << "          Processed: " << (bytes / (encryptionTime + decryptionTime)) << " bytes per second" << std::endl;
	
	g_totalTime += totalTime;
	g_totalBytes += bytes;
}

void performBasicEncryption () {
	//StringT input((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
	std::ifstream textFile("text.txt");
	StringT input((std::istreambuf_iterator<char>(textFile)), std::istreambuf_iterator<char>());
	
	testEncryption(input, BITS_50D);
}

#pragma mark -
// These functions are mostly for testing and profiling

void testDivisionSpeed () {
	Integer n = 837498234, d = 93840293, r, f, t;
	
	n.shiftLeft(128);
	d.shiftLeft(127);
	
	//n = 1000000000;
	//d = 1000;
	
	//n.generateRandomNumber(20000, 30000);
	//d.generateRandomNumber(100, 200);
	
	TimeT start = systemTime();
	for (unsigned i = 0; i < 10000; i += 1) {
		//std::cout << "Dividing " << n << " by " << d << std::endl;
	
		std::cout << ".";
		
		n.add(1);
		d.add(1);
		
		//f.setFractionSlow(n, d, r);
		//f.setFraction(n, d, r);
		
		Integer c;
		c.setProduct(f, d);
		c.add(r); // remainder
	
		// Check the result is correct
		assert(r < d);
		assert(n == c);
	}
	
	TimeT end = systemTime();
	std::cout << "Time = " << (end - start) << "s" << std::endl;
}

void benchmark (std::size_t bits) {
	TimeT start = systemTime();
	
	std::cerr << "***: Bits = " << bits << std::endl;
	
	std::size_t i = 0;
	for (; i < 30; i += 1) {
		std::cerr << "*** Run " << i << std::endl;
		generateKeyPair(bits);
		
		std::cerr << "***> Running Average = " << ((systemTime() - start) / (i+1)) << std::endl;
	}
	TimeT end = systemTime();
	
	std::cerr << "***> Bits = " << bits << std::endl;
	std::cerr << "***> Average Time = " << ((end - start) / i) << std::endl;
}

void testCalculateInverse () {
	std::string p = "45F71A13A848E9EA578CC2CB2D70622CD907D5F5B11F79A308E8E2F75322E731A26A3143E406ED121E1DB7892AE28F621CFE3AB5429A161972BB0D44E0B4FB88E475105E6F2645C394F89C97732B4F6694B0556C711E6F730749164820EC5B3984FBA536C65AF736861ED7F35963ED29EA5C0A25F134E5614649C55F7655EDF9";
	std::string q = "C7FCA7C4FC734A8124A6EB55BBDF46140E011FC6555014F2508F7A508BD35A2397D20CD7B96C2232DAF62AECEB0D1D4672B6D67AE63FC5DFBD97B19435C45B0D5FDE752E117577C1FFD189E4B8A9BDBF21B35BBF460E8C0F3E6EFABEB637C08C62473A97BC64D888013FD939AE149B52F02C1F807F23003E19C46D4A9EFF75EF";
	std::string e = "167BDD7BA946A130392A0CDE2BFECB787F6BDF727A2907B6AF7D3F24AA0562911C4635C07481A4DFDBDF60D411DF95C4768F660FB69C1B0FC96028A3AE932C02B3AD7EB0B78FE313EAC17A620E60F1D58ED8F5F440CBC29B7B285BBD6F154C196E6E8FB8C92C3B483A1B919F67046F45D2F2885C0012A07E272D2EE055462E07";

	Integer p1 = p, q1 = q;
	
	//std::cout << "p? " << p1.isProbablyPrime() << std::endl;
	//std::cout << "q? " << q1.isProbablyPrime() << std::endl;
	//std::cout << "e? " << q1.isProbablyPrime() << std::endl;
	
	p1.subtract(1);
	q1.subtract(1);

	Integer phi = 0;
	phi.setProduct(p1, q1);
	
	Integer d = 0;
	d.calculateInverse(e, phi);
	
	Integer ed;
	ed.setProduct(e, d);
	ed.modulus(phi);
	
	std::cerr << "phi = " << phi.toString() << std::endl
	          << "d = " << d.toString() << std::endl
			  << "ed = " << ed.toString() << std::endl;
}

void testAddition () {
	Integer x("31EB3579FFFFFFFFFFFFFFFFFFFFFFEC6FEBC427");
	Integer y("0000001390143BDA");
    //	  |      |      |      |      |      |      |      |
	Integer result("31EB357A00000000000000000000000000000001");
	
	x.add(y);
	
	assert(x == result);
}

#pragma mark -

int main (int argc, char ** argv) {
	
	// For testing key generation speed
	//for (std::size_t i = 1; i <= 16; i++)
	//	benchmark(128 * i);
	
	/*
	// For testing encryption / decryption speed
	std::ifstream inputFile("text.txt");
	StringT testData((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
	
	for (std::size_t i = 0; i < 30; i += 1) {
		testEncryption(testData, 1024);
	}
	
	std::cout << "*** Total Time: " << g_totalTime << "s; Bytes / Seconds: " << ((TimeT)(g_totalBytes / g_totalTime) / 1024.0) << std::endl;
	*/
	
	//testDivisionSpeed();
	
	performBasicEncryption();
}

// For single file build...
#include "Integer.cpp"
