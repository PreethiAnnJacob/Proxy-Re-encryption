package main

import (
	"crypto/sha512"
	"math/big"
	"crypto/rand"
	"randstring"
	"fmt"
	"crypto/aes"
	"io"
	"crypto/cipher"
	"bytes"
	"time"
)

type Params struct {
	q *big.Int
	P *big.Int
	lt int	
	lm int								
	lc int									
	lp int									
	lk int									
	lw int
	lu int
	lg int
	l0 int
	l3 int
	l5 int
}

type User struct {
	sk *big.Int
	pk *big.Int
}

type ReKey struct {
	R1 *big.Int
	R2 *big.Int
	R3 []byte
	R4 *big.Int
	R5 []byte
	R6 []byte
}

type Cipher1 struct {
	C1 *big.Int
	C2 []byte
	C3 []byte
	C4 *big.Int
	C5 []byte
}

type Cipher2 struct {
	D1 *big.Int
	D2 []byte
	D3 []byte
	D4 *big.Int
	D5 []byte
	D6 []byte
}

//----------------------------------------------------------------------Hashes-------------------------------------------------------------------

//----------------------------------------------------------------H0: Maps to a string-----------------------------------------------------------

func hash0 (t []byte, params Params) ([]byte) {
	h := sha512.New()
	if _, err := h.Write(t); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	return h1[0 : params.l0]
}

//------------------------------------------------------H1: Maps to an element in cyclic group--------------------------------------------------

func hash1 (c []byte, x *big.Int, X *big.Int) (*big.Int) {
	h := sha512.New()
	if _, err := h.Write(c); err != nil {
		panic(err)
	}
	if _, err := h.Write(x.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(X.Bytes()); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	r := new(big.Int).SetBytes(h1) 
	return r
}

//----------------------------------------------------------------H2: Maps to a string-----------------------------------------------------------

func hash2 (t *big.Int, params Params) ([]byte) {
	h := sha512.New()
	if _, err := h.Write(t.Bytes()); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	return h1[0 : params.lk]
}

//----------------------------------------------------------------H3: Maps to a string-----------------------------------------------------------

func hash3 (m []byte, t *big.Int, params Params) ([]byte) {
	h := sha512.New()
	if _, err := h.Write(m); err != nil {
		panic(err)
	}
	if _, err := h.Write(t.Bytes()); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	return h1[0 : params.l3]
}

//------------------------------------------------------H4: Maps to an element in cyclic group--------------------------------------------------

func hash4 (C1 *big.Int, C2 []byte, C3 []byte, alpha []byte, X *big.Int) (*big.Int) {
	h := sha512.New()
	if _, err := h.Write(C1.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(C2); err != nil {
		panic(err)
	}
	if _, err := h.Write(C3); err != nil {
		panic(err)
	}
	if _, err := h.Write(alpha); err != nil {
		panic(err)
	}
	if _, err := h.Write(X.Bytes()); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	r := new(big.Int).SetBytes(h1) 
	return r
}

//----------------------------------------------------------------H5: Maps to a string-----------------------------------------------------------

func hash5 (t []byte, x *big.Int, X *big.Int, params Params) ([]byte) {
	h := sha512.New()
	if _, err := h.Write(t); err != nil {
		panic(err)
	}
	if _, err := h.Write(x.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(X.Bytes()); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	return h1[0 : params.l5]
}

//------------------------------------------------------H6: Maps to an element in cyclic group--------------------------------------------------

func hash6 (w []byte, x *big.Int, xI *big.Int, xJ *big.Int) (*big.Int) {
	h := sha512.New()
	if _, err := h.Write(w); err != nil {
		panic(err)
	}
	if _, err := h.Write(x.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(xI.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(xJ.Bytes()); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	r := new(big.Int).SetBytes(h1) 
	return r
}

//------------------------------------------------------H7: Maps to an element in cyclic group--------------------------------------------------

func hash7 (R *big.Int, X *big.Int) (*big.Int) {
	h := sha512.New()
	if _, err := h.Write(R.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(X.Bytes()); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	r := new(big.Int).SetBytes(h1) 
	return r
}

//----------------------------------------------------------------H8: Maps to a string-----------------------------------------------------------

func hash8 (l *big.Int, X *big.Int, params Params) ([]byte) {
	h := sha512.New()
	if _, err := h.Write(l.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(X.Bytes()); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	return h1[0 : params.lw + params.lp]
}

//------------------------------------------------------H9: Maps to an element in cyclic group--------------------------------------------------

func hash9 (D []byte, p *big.Int) (*big.Int) {
	h := sha512.New()
	if _, err := h.Write(D); err != nil {
		panic(err)
	}
	if _, err := h.Write(p.Bytes()); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	r := new(big.Int).SetBytes(h1) 
	return r
}

//----------------------------------------------------------------HC: Maps to a string-----------------------------------------------------------

func hashC (C []byte, params Params) ([]byte) {
	h := sha512.New()
	if _, err := h.Write(C); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil) 
	return h1[0 : params.lc]
}

//--------------------------------------------------------------------Setup-----------------------------------------------------------------------

func Setup (K int, params Params) (Params) {
	params.q = big.NewInt(16381) 							//Choosing prime order q
	params.P = big.NewInt(16379)							//Generator of group of order q
	params.lt = 32									//Size of tag
	params.lc = 64									//Size of ciphertext
	params.lp = K									
	params.lk = 32									//Size of symmetric key used
	params.lw = K / 2
	params.lu = 2 * K
	params.l0 = K
	params.l3 = K
	params.l5 = K

	return params
}

//---------------------------------------------------------------Key Generation------------------------------------------------------------------

func KeyGen (user User, params Params) (User){
	x , err := rand.Int(rand.Reader, params.q)					 //Secret Key calculation : A random value x within Zq+
	if err != nil {
		panic(err)
	}
	user.sk = x
	var X = new(big.Int).Mul(user.sk, params.P)					//Public key calculation : x*P
	user.pk = X

	return user
}

//--------------------------------------------------------Re-encryption Key Generation----------------------------------------------------------

func ReKeyGen (rekey ReKey, userI User, userJ User, cw []byte, tag []byte, params Params) (ReKey, Params) {
	const charset = "01"
	w := []byte(randstring.StringWithCharset(params.lw, charset))			//Generating a random string of length lw
	var hc = hash1(cw, userI.sk, userI.pk)						//hc = H1(cw, xi, Xi)
	var xX = new(big.Int).Mul(userI.sk, userJ.pk)
	var r = hash6(w, xX, userI.pk, userJ.pk)					//r = H6(w, xi*Xj, Xi, Xj)
	var s = hash7(r, userJ.pk)							//s = H7(r, Xj)
	var gamma = new(big.Int).Mul(r, userJ.pk)					//gamma = r*Xj
	
	rekey.R1 = new(big.Int).Sub(s, hc)						//R1 = s-hc
	rekey.R2 = new(big.Int).Mul(r, params.P)					//R2 = r*P
	var X = (userI.pk).Bytes()
	params.lg = len(X)
	var length = params.lw + params.lg
	var wX = append(w[:], X[:]...)
	wX = wX[0 : length]
	var hash = hash8(gamma, userJ.pk, params)
	hash = hash[0 : length]
	var r3 = make([]byte, length)
	for i := 0; i<length; i++ {
		r3[i] = wX[i] ^ hash[i]
	}
	rekey.R3 = append(r3[:], rekey.R3[:]...)					//R3 = (w||Xi) xor H8(gamma, Xj)
	rekey.R4 = hash6(w, gamma, userI.pk, userJ.pk)					//R4 = H6(w, gamma, Xi, Xj)	
	rekey.R5 = hash5(tag, userI.sk, userI.pk, params)				//R5 = H5(tw, xi, Xi)
	rekey.R6 = hash0(tag, params)							//R6 = H0(tw)

	fmt.Println("Re-encryption key generated successfully")	
	return rekey, params
}

//-----------------------------------------------------------Symmetric Encryption-------------------------------------------------------------

func SymEncrypt (key []byte, plainText []byte) ([]byte) {
	c, err := aes.NewCipher(key)
	if err != nil {
	fmt.Println(err)
	}
	gcm, err := cipher.NewGCM(c)							//Galois/Counter Mode (GCM) is a mode of operation   
	if err != nil {									//for symmetric-key cryptographic block ciphers
	fmt.Println(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {			//Populates nonce with a cryptographically secure
	fmt.Println(err)								//random sequence
	}
	var cipher = gcm.Seal(nonce, nonce, plainText, nil)				//Seal encrypts and authenticates plaintext
	return cipher
}


//-------------------------------------------------------------Self Encryption----------------------------------------------------------------

func SelfEncrypt (m []byte, tag []byte, C Cipher1, user User, params Params) (Cipher1) {
	t, err := rand.Int(rand.Reader, params.q) 					//Selection of a random t value from Zq*
	if err != nil {
		panic(err)
	} 
	var ht = hash1(tag, user.sk, user.pk)						//ht = H1(tw, xi, Xi)
	C.C1 = new(big.Int).Add(t, ht)							//C1 = t + ht
	var key = hash2(t, params)							//key  = H2(t)
	C.C2 = SymEncrypt(key, m)							//C2 = Sym.Encrypt(m, key)
	C.C3 = hash3(m, t, params)							//C3 = H3(m, t)
	var alpha = hash5(tag, user.sk, user.pk, params)				//alpha = H5(tw, xi, Xi)
	C.C4 = hash4(C.C1, hashC(C.C2, params), C.C3, alpha, user.pk)			//C4 = H4(C1, Hc(C2), C3, alpha, Xi)
	C.C5 = hash0(tag, params)							//C5 = H0(tw)
	
	fmt.Println("I level Ciphertext encrypted successfully")	
	return C			
}

//--------------------------------------------------------------Re-Encryption--------------------------------------------------------------------

func ReEncrypt(C Cipher1, D Cipher2, user User, rekey ReKey, params Params) (Cipher2){
	const charset = "01"		
	u := []byte(randstring.StringWithCharset(params.lu, charset))  			//Random string selection 
	
	var hash = hashC(C.C2, params)
	var input1 = (C.C4).Cmp(hash4(C.C1, hash, C.C3, rekey.R5, user.pk))		//Checking whether C4 != H4(C1, HC(C2), C3, R5, X)
	var input2 = bytes.Compare(C.C5, rekey.R6)					//Or C5 != R6					
	var result = input1 == 1 || input2 == 1
	if result == true {
		D.D1 = nil
		D.D2 = nil
		D.D3 = nil
		D.D4 = nil
		D.D5 = nil
		D.D6 = nil
		return D
	} 
	D.D2 = C.C2
	D.D3 = C.C3
	D.D4 = rekey.R2
	D.D5 = rekey.R3
	D.D6 = u

	var beta = hash9(u, rekey.R4)							//B = H9(u, R4)
	var t1 = new(big.Int).Add(C.C1, rekey.R1)
	t1 = new(big.Int).Mod(t1, params.q)
	var t2 = new(big.Int).Mul(beta, t1)						
	D.D1 = new(big.Int).Mod(t2, params.q)						//D1 = B(C1+R1) 
				
	fmt.Println("II level Ciphertext encrypted successfully")	
	return D
}

//----------------------------------------------------------Symmetric Decryption-----------------------------------------------------------------

func SymDecrypt (key []byte, cipherText []byte) ([]byte) {
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}
	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		fmt.Println(err)
	}
	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		fmt.Println(err)
	}
	return plainText
}

//------------------------------------------------------------Self Decryption--------------------------------------------------------------------

func SelfDecrypt (C Cipher1, user User, tag []byte, params Params) ([]byte) {
	var alpha = hash5(tag, user.sk, user.pk, params)			//alpha = H4(tw, xi, Xi)
	var hash = hashC(C.C2, params)
	if ((C.C4).Cmp(hash4(C.C1, hash, C.C3, alpha, user.pk))	== 1){		//Checking whether C4 != H4(C1, HC(C2), C3, alpha, X)
		return nil
	}
	var ht = hash1(tag, user.sk, user.pk)					//ht = H1(tw, xi, Xi)
	var t = new(big.Int).Sub(C.C1, ht)					//t = C1 - ht
	var key = hash2(t, params)						//key = H2(t)
	var m = SymDecrypt(key, C.C2)						//m = Sym.Decrypt(C2, key)
	if(bytes.Compare(C.C3, hash3(m, t, params)) == 0){			//Checking whether C3 = H3(m, t)
		fmt.Println("I level Ciphertext decrypted successfully")
		return m
	}
	return nil
}
//-------------------------------------------------------------Re-Decryption---------------------------------------------------------------------

func ReDecrypt (D Cipher2, user User, params Params) ([]byte) {
	var gamma = new(big.Int).Mul(user.sk, D.D4)				//gamma = xj * D4
	var length = params.lw + params.lg
	var hash = hash8(gamma, user.pk, params)
	hash = hash[0 : length]
	var wX = make([]byte, length)
	for i := 0; i<length; i++ {
		wX[i] = D.D5[i] ^ hash[i]					//w||Xi = D5 xor H8(gamma, Xj)
	}
	var w = wX[0 : params.lw]
	var X = wX[params.lw : ]
	var Xi = new(big.Int)
	Xi.SetBytes(X)
	var xX = new(big.Int).Mul(user.sk, Xi)
	var r = hash6(w, xX, Xi, user.pk)					//r = H6(w, xj*Xi, Xi, Xj)
	var s = hash7(r, user.pk)						//s = H7(r, Xj)	
	var p = hash6(w, gamma, Xi, user.pk)					//p = H6(w, gamma, Xi, Xj)
	var beta = hash9(D.D6, p)						//B = H9(D6, p)
	var betaInv = new(big.Int).ModInverse(beta, params.q) 
	var t1 = new(big.Int).Mul(betaInv, D.D1)
	t1 = new(big.Int).Mod(t1, params.q)
	var t = new(big.Int).Sub(t1, s)						//t = (B^-1 * D1) - s
	t = new(big.Int).Mod(t, params.q)
	var key = hash2(t, params)						//key = H2(t)
	var m = SymDecrypt(key, D.D2)						//m = Sym.Decrypt(D2, key)
	if(bytes.Compare(D.D3, hash3(m, t, params)) == 0){			//Checking whether D3 = H3(m, t)
		fmt.Println("II level Ciphertext decrypted successfully")
		return m
	}
	return nil
}

func main () {
	var K = 32
	var params Params
	params = Setup(K, params)

	m := []byte("Hello World, How are you.Hello World, How are you.")
	params.lm = len(m)
	var userI, userJ User
	const charset = "01"
	cw := []byte(randstring.StringWithCharset(params.lt, charset)) 
	tag := cw
	var rekey ReKey
	var C Cipher1
	var D Cipher2
	
	start1 := time.Now()
	userI = KeyGen(userI, params)
	elapsed1 := time.Since(start1)
	userJ = KeyGen(userJ, params)

	start2 := time.Now()
	rekey, params = ReKeyGen(rekey, userI, userJ, cw, tag, params)
	elapsed2 := time.Since(start2)

	start3 := time.Now()
	C = SelfEncrypt(m, tag, C, userI, params)
	elapsed3 := time.Since(start3)

	start4 := time.Now()
	D = ReEncrypt(C, D, userI, rekey, params)
	elapsed4 := time.Since(start4)

	start5 := time.Now()
	var m1 = SelfDecrypt(C, userI, tag, params)
	elapsed5 := time.Since(start5)

	start6 := time.Now()
	var m2 = ReDecrypt(D, userJ, params)
	elapsed6 := time.Since(start6)

	fmt.Println()
	fmt.Println("Time Taken for Key Generation			:  ", elapsed1)
	fmt.Println("Time Taken for Re-encryption Key Generation	:  ", elapsed2)
	fmt.Println("Time Taken for Self-Encryption			:  ", elapsed3)
	fmt.Println("Time Taken for Re-encryption			:  ", elapsed4)
	fmt.Println("Time Taken for Self-Decryption			:  ", elapsed5)
	fmt.Println("Time Taken for Re-decyption			:  ", elapsed6)
	fmt.Println()

	fmt.Println()
	fmt.Println("Message encrypted     : ",string(m[:]))
	fmt.Println("Message decrypted I   : ",string(m1[:]))
	fmt.Println("Message decrypted II  : ",string(m2[:]))
}

