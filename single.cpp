/*
 *  single.cpp
 *  RSA
 *
 *  Created by Samuel Williams on 20/08/10.
 *  Copyright 2010 Orion Transfer Ltd. All rights reserved.
 *
 */

#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>

// MP Details : http://www.cosc.canterbury.ac.nz/tad.takaoka/cosc413/division.c
// RSA Details : http://www.it.uu.se/edu/course/homepage/security/vt09/labs/lab2

typedef uint64_t BigIntT;
typedef int64_t SBigIntT;
typedef std::basic_string<unsigned char> StringT;

// This is a robust primality test for single precision numbers.
// It returns true if a number is a prime. It is used for checking
// correctness of probabilistic prime number generator.
bool robustPrimeTest (BigIntT p) {
	for (BigIntT d = 2; d <= p/2; d += 1) {
		if ((p % d) == 0) {
			return false;
		}
	}
	
	return true;
}

// Returns a large random number.
BigIntT generateRandomNumber () {
	return (BigIntT)rand() * (BigIntT)rand() * (BigIntT)rand();
}

// Returns a large random number between min and max.
BigIntT generateRandomNumber (BigIntT min, BigIntT max) {
	return min + (generateRandomNumber() % (max - min));
}

// Returns the greatest common divisor of a and b.
BigIntT greatestCommonDivisor (BigIntT a, BigIntT b) {
	if (b == 0) {
		return a;
	} else {
		return greatestCommonDivisor(b, a % b);
	}
}


// This function calculations the power of b^e mod phi
// As long as 
//		b*b is smaller than max(BigIntT) 
//		b*phi is smaller than max(BigIntT)
// we will not have overflow.
BigIntT calculatePower (BigIntT b, BigIntT e, BigIntT m) {
	BigIntT result = 1;
		
	while (e != 0) {
		if (e & 1) {
			result = (result * b) % m;
		}
		
		e = e >> 1;
		b = (b * b) % m;
	}
	
	return result;
}

// This function implements simple jacobi test.
// We can expect compiler to perform tail-call optimisation.
SBigIntT jacobi (SBigIntT a, SBigIntT b) {
	if (a == 0 || a == 1) {
		return a;
	} else if (a % 2 == 0) {
		if (((b*b - 1) / 8) % 2 == 0) {
			return jacobi(a/2, b);
		} else {
			return -jacobi(a/2, b);
		}
	} else if ((((a-1) * (b-1)) / 4) % 2 == 0) {
		return jacobi(b % a, a);
	} else {
		return -jacobi(b % a, a);
	}
}

// Alternative method : http://en.wikipedia.org/wiki/Miller-Rabin_primality_test
// This function implements : http://en.wikipedia.org/wiki/Solovay-Strassen_primality_test
bool testPrime (BigIntT p) {
	int tests = 10;
	
	if (p == 2) {
		return true;
	}
	
	while (tests-- > 0) {
		BigIntT a = generateRandomNumber(2, p);

		if (greatestCommonDivisor(a, p) == 1) {
			BigIntT l = calculatePower(a, (p-1)/2, p);
			SBigIntT j = jacobi(a, p);
			
			// j % p == l
			if ((j == -1) && (l == p-1) || (j == l)) {
				// So far so good...
			} else {
				// p is composite
				return false;
			}
		} else {
			// p is composite
			return false;
		}
	}
	
	return true;
}

// Find a prime min < p < max
BigIntT generatePrime (BigIntT min, BigIntT max) {
	while (true) {
		BigIntT p = generateRandomNumber(min, max);
		p |= 1; // Ensure odd number
		
		// Avoid Mersenne primes
		if ((p+1) == 0 || ((p+1) & p) == 0) {
			continue;
		}
		
		if (testPrime(p)) {
			return p;
		}
	}
}

//	Computes inv = u^(-1) mod v */
//	Ref: Knuth Algorithm X Vol 2 p 342
//		ignoring u2, v2, t2
//		and avoiding negative numbers.
//		Returns non-zero if inverse undefined.
BigIntT calculateInverse (BigIntT u, BigIntT v) {
	BigIntT u1 = 1, u3 = u, v1 = 0, v3 = v;	
	bool odd = false;
	
	while (v3 != 0) {
		BigIntT q = u3 / v3, t3 = u3 % v3;
		BigIntT w = q * v1;
		BigIntT t1 = u1 + w;
		
		u1 = v1;
		v1 = t1;
		u3 = v3;
		v3 = t3;
		
		odd = !odd;
	}
	
	if (odd) {
		return v - u1;
	} else {
		return u1;
	}
}

// Prints out a std::vector of values for debugging.
template <typename AnyT>
std::ostream & operator<< (std::ostream & output, std::vector<AnyT> & v) {
	output << "{";
	bool first = true;
	
	for (unsigned i = 0; i < v.size(); i += 1) {
		if (!first) {
			output << ", ";
		} else {
			first = false;
		}
		
		output << v[i];
	}
	
	output << "}";
	
	return output;
}

// A simple function for testing the accuracy of prime number generation.
// This function man be very slow; it is designed for testing purposes only.
void testPrimeNumberGeneration () {
	int total, correct;
	
	total = correct = 0;
	
	for (int i = 2; i < 10000; i += 1) {
		total += 1;
		
		bool pt = testPrime(i);
		bool rpt = robustPrimeTest(i);
		
		if (pt == rpt) {
			correct += 1;
		} else {
			std::cerr << "Failed for " << i << " : Probabilistic Method: " << pt << " Robust Method: " << rpt << std::endl;
		}
	}
	
	std::cout << "Prime Generation Accuracy = " << ((double)correct / (double)total) * 100.0 << "%" << std::endl;
	
	total = correct = 0;
	
	for (int i = 0; i < 10000; i += 1) {
		BigIntT p = generatePrime(1, 10000);
				
		total += 1;
		// O(2^N)
		if (robustPrimeTest(p)) {
			correct += 1;
		}
	}
	
	std::cout << "Prime Test Accuracy = " << ((double)correct / (double)total) * 100.0 << "%" << std::endl;
}

BigIntT findPrimeLessThan (BigIntT max) {
	while (max > 0) {
		max -= 1;
		
		if (testPrime(max)) {
			return max;
		}
	}
	
	return 0;
}

// This function generates a test pattern for testing.
unsigned char TEST_PATTERN[] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xFF,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

StringT testPattern () {
	return StringT(TEST_PATTERN, TEST_PATTERN + sizeof(TEST_PATTERN));
}

// This function packs two 8-bit characters into an array of integers.
// Characters are stored from LSB to MSB.
void pack (const StringT & text, std::vector<BigIntT> & packed) {
	packed.resize((text.size() + 1) / 2);
	
	for (std::size_t i = 0; i < text.size(); i += 2) {
		BigIntT p = text[i];
		
		if (i+1 < text.size())
			p |= (text[i+1] << 8);
		
		packed[i/2] = p;
	}
}

// This function unpacks two 8-bit characters into an array of integers.
// Characters are stored from LSB to MSB.
void unpack (const std::vector<BigIntT> & packed, StringT & text) {
	text.resize(packed.size() * 2);
	
	for (std::size_t i = 0; i < packed.size(); i += 1) {
		BigIntT p = packed[i];
		
		text[(i*2)] = p & 0xFF;
		text[(i*2)+1] = p >> 8;
	}
}

// Choosing 256 as minimum ensures that phi should be big enough to encode 2 8-bit values.
const BigIntT MIN_PRIME = 1<<8;
const BigIntT MAX_PRIME = 1<<16;

// Turn on for arithemtic overflow test
// #define ARITHMETIC_TEST

int main (int argc, char * const argv[]) {
	// Seed the random number generator.
	// BSD API
	// sranddev();
	
	timeval t1;
	gettimeofday(&t1, NULL);
	srand(t1.tv_usec * t1.tv_sec);	
	
#ifdef ARITHMETIC_TEST
	// This function tests prime number generation.
	testPrimeNumberGeneration();
	
	// Use a test pattern
	StringT input = testPattern();	
#else
	// Read test message from stdin
	StringT input((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
#endif
	
	BigIntT p, q, n, e, d;
	
#ifdef ARITHMETIC_TEST
	// Check Aritmetic - two largest 32-bit prime numbers.
	p = findPrimeLessThan(MAX_PRIME);
	q = findPrimeLessThan(p);
#else
	// Find two large primes using probabilistic method.
	p = generatePrime(MIN_PRIME, MAX_PRIME);
	
	do {
		q = generatePrime(MIN_PRIME, MAX_PRIME);
	} while (q == p);
#endif

	// Compute (e, n) and (d, n) keys.
	n = p * q;

	std::cerr << "p = " << p << " q = " << q << " n = " << n << std::endl;	
		
#ifdef ARITHMETIC_TEST
	// Check Arithmetic - largest possible prime number less than n.
	e = findPrimeLessThan(n);
#else
	// Generate public key - does this need to use Euclidean algorithm here??
	e = generatePrime(MIN_PRIME, n);
#endif
		
	assert(greatestCommonDivisor(e, p-1) == 1);
	assert(greatestCommonDivisor(e, q-1) == 1);
	
	// Generate private key
	BigIntT phi = (p-1)*(q-1);
	d = calculateInverse(e, phi);
	
	std::cerr << "phi = " << phi << " d = " << d << " ed = " << (e * d) % phi << std::endl;
	std::cerr << "public = " << n << ", " << e << " private = " << n << ", " << d << std::endl;
	
	// Process the input data into a packed message.
	std::vector<BigIntT> message;
	pack(input, message);
		
	std::vector<BigIntT> cipher, decipher;
		
	std::cout << " Message: " << message << std::endl;
	
	for (unsigned i = 0; i < message.size(); i += 1) {
		BigIntT m = calculatePower(message[i], e, n);
		
		cipher.push_back(calculatePower(message[i], e, n));
	}
	
	std::cout << "  Cipher: " << cipher << std::endl;
	
	for (unsigned i = 0; i < cipher.size(); i += 1) {
		decipher.push_back(calculatePower(cipher[i], d, n));
	}
	
	std::cout << "Decipher: " << decipher << std::endl;

	// Unpack the data.
	StringT output;	
	unpack(decipher, output);
	
#ifdef ARITHMETIC_TEST
	std::cout << "Result: " << (testPattern() == output) << std::endl;
#else
	std::string ascii(output.begin(), output.end());
	std::cout << "Decoded Message: " << std::endl << ascii << std::endl;
#endif
}
