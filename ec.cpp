#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <utility>
#include <cassert>
#include "ec_ops.h"
#include "uberzahl.h"
using namespace std;

Zp Zp::inverse() const{
    uberzahl m = PRIME;
    uberzahl y = "0", x = "1";
    uberzahl a = value;
    while (a > "1") {
        uberzahl q = a / m;
        uberzahl t = m;
        m = a - q * m; // changed from m = a % m
        a = t;
        t = y;
        y = x - q * y;
        x = t;
    }
    if (x < "0") {
        x = x + m;
    }
    return x;
}


ECpoint ECpoint::operator + (const ECpoint &a) const {
	// Implement  elliptic curve addition
    Zp zero("0");
    ECpoint sum;
    if (a.infinityPoint == true && infinityPoint == true) {
        sum = ECpoint(true);
    }
    else if (a.infinityPoint == true && infinityPoint == false) {
        sum = ECpoint(x, y);
    }
    else if (infinityPoint == true && a.infinityPoint == false) {
        sum = a;
    }
    // sum = P (self) + Q (a)
    else {
        if (!(*this == a) && !(x == a.x)) {
            Zp lambda = (a.y - y) * (a.x - x).inverse();
            sum.x = (lambda * lambda) - x - a.x;
            sum.y = (lambda * (x - sum.x)) - y;
        }
        else if (*this == a && !((y + y) == zero)) {
            Zp x_squared = x * x;
            Zp lambda = (x_squared + x_squared + x_squared + A) * (y + y).inverse(); // y + y faster than 2y
            sum.x = (lambda * lambda) - (x + x);
            sum.y = (lambda * (x - sum.x)) - y;
        }
    }
    return sum;
}


ECpoint ECpoint::repeatSum(ECpoint p, uberzahl v) const {
	//Find the sum of p+p+...+p (vtimes)
    assert(v != "0");
    if (v == "1") {
        return p;
    }
    if ((v & uberzahl("1")) == uberzahl("1")) {
        return p + repeatSum(p + p, v >> 1);
    }
    return repeatSum(p + p, v >> 1);
}

Zp ECsystem::power(Zp val, uberzahl pow) {
	//Find the product of val*val*...*val (pow times)
    if (pow == "0") {
        return Zp("1");
    }
    if (pow == "1") {
        return val;
    }
    if ((pow & uberzahl("1")) == uberzahl("1")) {
        return val * power(val * val, pow >> 1);
    }
    return power(val * val, pow >> 1);
}


uberzahl ECsystem::pointCompress(ECpoint e) {
	//It is the gamma function explained in the assignment.
	//Note: Here return type is mpz_class because the function may
	//map to a value greater than the defined PRIME number (i.e, range of Zp)
	//This function is fully defined.	
	uberzahl compressedPoint = e.x.getValue();
	compressedPoint = compressedPoint<<1;
	
	if(e.infinityPoint) {
		cout<<"Point cannot be compressed as its INF-POINT"<<flush;
		abort();
		}
	else {
        if ((e.y.getValue() & uberzahl("1")) == uberzahl("1"))
			compressedPoint = compressedPoint + 1;
		}
		//cout<<"For point  "<<e<<"  Compressed point is <<"<<compressedPoint<<"\n";
		return compressedPoint;

}

ECpoint ECsystem::pointDecompress(uberzahl compressedPoint){
	//Implement the delta function for decompressing the compressed point
    smallType lastBit = compressedPoint.bit(0);
    uberzahl xR = compressedPoint >> 1;
    uberzahl alpha = xR * xR * xR - (xR + xR + xR) + "152961";
    Zp alphaZp = Zp(alpha);
    uberzahl pow1 = (PRIME - "1") >> 1;
    Zp alphaResidue = power(alphaZp, pow1);
    Zp(yR);
    if (alphaResidue == 1) {
        uberzahl pow2 = (PRIME + "1") >> 2;
        Zp alphaSqrt1 = power(alphaZp, pow2);
        Zp alphaSqrt2 = Zp(PRIME) - alphaSqrt1;
        uberzahl alphaSqrt1Uber = alphaSqrt1.getValue();
        
        if (lastBit == 0) {
            yR = (alphaSqrt1Uber.bit(0) == 0) ? alphaSqrt1 : alphaSqrt2;
        }
        else {
            yR = (alphaSqrt1Uber.bit(0) == 1) ? alphaSqrt1 : alphaSqrt2;
        }
    }
    
	return ECpoint(xR, yR);
}


pair<pair<Zp,Zp>,uberzahl> ECsystem::encrypt(ECpoint publicKey, uberzahl privateKey,Zp plaintext0,Zp plaintext1){
	// You must implement elliptic curve encryption
	//  Do not generate a random key. Use private key passed from the main function
    ECpoint G((Zp(GX)), Zp(GY));
    ECpoint Q = publicKey.repeatSum(G, privateKey);
    ECpoint R = publicKey.repeatSum(publicKey, privateKey);
    Zp C0 = plaintext0 * R.x;
    Zp C1 = plaintext1 * R.y;
    uberzahl C2 = pointCompress(Q);
	
	return make_pair(make_pair(C0, C1), C2);
}


pair<Zp,Zp> ECsystem::decrypt(pair<pair<Zp,Zp>, uberzahl> ciphertext){
	// Implement EC Decryption
    ECpoint R = ECpoint().repeatSum(pointDecompress(ciphertext.second), privateKey);
    Zp M0 = ciphertext.first.first * R.x.inverse();
    Zp M1 = ciphertext.first.second * R.y.inverse();
	return make_pair(M0, M1);
}


/*
 * main: Compute a pair of public key and private key
 *       Generate plaintext (m1, m2)
 *       Encrypt plaintext using elliptic curve encryption
 *       Decrypt ciphertext using elliptic curve decryption
 *       Should get the original plaintext
 *       Don't change anything in main.  We will use this to 
 *       evaluate the correctness of your program.
 */


int main(void){
    ios_base::sync_with_stdio(false);
	srand(time(0));
	ECsystem ec;
	unsigned long incrementVal;
	pair <ECpoint, uberzahl> keys = ec.generateKeys();
    
	Zp plaintext0(MESSAGE0);
	Zp plaintext1(MESSAGE1);
	ECpoint publicKey = keys.first;
	cout<<"Public key is: "<<publicKey<<"\n";
	
	cout<<"Enter offset value for sender's private key"<<endl;
	cin>>incrementVal;
	uberzahl privateKey = XB + incrementVal;
	
	pair<pair<Zp,Zp>, uberzahl> ciphertext = ec.encrypt(publicKey, privateKey, plaintext0,plaintext1);	
	cout<<"Encrypted ciphertext is: ("<<ciphertext.first.first<<", "<<ciphertext.first.second<<", "<<ciphertext.second<<")\n";
    
	pair<Zp,Zp> plaintext_out = ec.decrypt(ciphertext);
	
	cout << "Original plaintext is: (" << plaintext0 << ", " << plaintext1 << ")\n";
	cout << "Decrypted plaintext: (" << plaintext_out.first << ", " << plaintext_out.second << ")\n";


	if(plaintext0 == plaintext_out.first && plaintext1 == plaintext_out.second)
		cout << "Correct!" << endl;
	else
		cout << "Plaintext different from original plaintext." << endl;
	return 1;

}


