package main

import (
	"fmt"
	"crypto/rand"
	"randstring"
	"math/big"
	"crypto/sha512"
	"floatToint"
	"strconv"
	"math"
	"time"
)

type Params struct {
	q *big.Int
	P *big.Int
	Ppub *big.Int
	l0 int
	l1 int
	lID int
}

type PartialPublicKey struct {
	X *big.Int
	Y *big.Int
	d *big.Int
}

type PartialSecretKey struct{
	y *big.Int
}

type UserPublicKey struct {
	Z *big.Int
}

type UserSecretKey struct {
	z *big.Int
}

type PublicKey struct {
	X *big.Int
	Y *big.Int
	Z *big.Int
	d *big.Int
}

type SecretKey struct {
	z *big.Int	
	y *big.Int
}

type User struct {
	ID []byte
	PPK PartialPublicKey
	PSK PartialSecretKey
	UPK UserPublicKey
	USK UserSecretKey
	PK PublicKey
	SK SecretKey
}

type ReKey struct{
	a *big.Int
	b *big.Int
	V *big.Int
	W *big.Int
}

type Cipher1 struct {
	C1 *big.Int
	C2 *big.Int
	C3 []byte
	C4 *big.Int
}

type Cipher_ struct{
	C1_ *big.Int
	C2_ *big.Int
}

type Cipher2 struct {
	D1 *big.Int
	D2 *big.Int
	D3 []byte
	D4 *big.Int
	D5 *big.Int
}


//------------------------------------------------------------------Hashes------------------------------------------------------------

//----------------------------------------------------H: Maps to an element in cyclic group-------------------------------------------

func hash_ (ID []byte, C1 *big.Int, C1_ *big.Int, C3 []byte) (*big.Int) {
	h := sha512.New()
	if _, err := h.Write(ID); err != nil {
		panic(err)
	}
	if _, err := h.Write(C1.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(C1_.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(C3); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	r := new(big.Int).SetBytes(h1)
	return r
}

//---------------------------------------------------H1: Maps to an element in cyclic group-------------------------------------------

func hash1 (ID []byte, X *big.Int, Y *big.Int) (*big.Int) {
	h := sha512.New()
	if _, err := h.Write(ID); err != nil {
		panic(err)
	}
	if _, err := h.Write(X.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(Y.Bytes()); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	r := new(big.Int).SetBytes(h1)
	return r
}

//-------------------------------------------------H2: Maps to an element in cyclic group----------------------------------------------

func hash2 (AB *big.Int) (*big.Int) {
	h := sha512.New()
	if _, err := h.Write(AB.Bytes()); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	r := new(big.Int).SetBytes(h1)
	return r
}

//------------------------------------------------H3: Maps to an element in cyclic group------------------------------------------------

func hash3 (V *big.Int) (*big.Int) {
	h := sha512.New()
	if _, err := h.Write(V.Bytes()); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	r := new(big.Int).SetBytes(h1)
	return r
}

//------------------------------------------------H4: Maps to an element in cyclic group-------------------------------------------------

func hash4 (m []byte, p []byte) (*big.Int) {
	h := sha512.New()
	if _, err := h.Write(m); err != nil {
		panic(err)
	}
	if _, err := h.Write(p); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	r := new(big.Int).SetBytes(h1)
	return r
}

//---------------------------------------------------------H5: Maps to a string-----------------------------------------------------------

func hash5 (Y *big.Int, Z *big.Int) ([]byte) {
	h := sha512.New()
	if _, err := h.Write(Y.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(Z.Bytes()); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	return h1
}

//------------------------------------------------H6: Maps to an element in cyclic group---------------------------------------------------

func hash6 (C1 *big.Int, C2 *big.Int, C3 []byte) (*big.Int) {
	h := sha512.New()
	if _, err := h.Write(C1.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(C2.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(C3); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	r := new(big.Int).SetBytes(h1) 
	return r
}

//---------------------------------------------------------------Setup----------------------------------------------------------------------

func Setup (params Params, lambda int) (Params, *big.Int ) {	
	params.q = big.NewInt(16381) 								//Choosing prime order q
	params.P = big.NewInt(16379)								//Generator of group of order q

	start := time.Now()
	s, err := rand.Int(rand.Reader, params.q) 						//Selection of a random s value from Zq*	
	if err != nil {
		panic(err)
	} 
	elapsed := time.Since(start)
	fmt.Println("\nTime taken by random number generation: ",elapsed)

	params.Ppub = new(big.Int).Mul(s, params.P) 						// Ppub = s*P
	params.l1 = lambda
	return params, s
}


//----------------------------------------------------------ID Generation-------------------------------------------------------------------

func GenerateID (length int) ([]byte) {
	const charset = "01"
	ID := []byte(randstring.StringWithCharset(length, charset)) 
	return ID
}
	

//------------------------------------------------------Partial Key Extraction--------------------------------------------------------------

func PartialKeyExtract (s *big.Int, user User,params Params) (User) {
	x, err := rand.Int(rand.Reader, params.q) 						//Selection of a random x value from Zq*
	if err != nil {
		panic(err)
	} 
	user.PPK.X = new(big.Int).Mul(x, params.P)			 			//X = x*P

	y, err := rand.Int(rand.Reader, params.q) 						//Selection of a random y value from Zq*
	if err != nil {
		panic(err)
	} 
	user.PSK.y = y
	user.PPK.Y = new(big.Int).Mul(user.PSK.y, params.P) 					//Y = y*P
	
	var Q = hash1(user.ID, user.PPK.X, user.PPK.Y) 						//q = H1(ID, X, Y)
	var t = new(big.Int).Mul(Q, s)
	var u = new(big.Int).Add(x, t)
	user.PPK.d = new(big.Int).Mod(u, params.q) 						//d = (x + Q*s) % q
	return user
}

//--------------------------------------------------------User Key Generation-------------------------------------------------------------

func UserKeyGen (user User, params Params) (User) {
	z, err := rand.Int(rand.Reader, params.q)						//Selection of a random z value from Zq*
	if err != nil {
		panic(err)
	} 
	user.USK.z = z
	user.UPK.Z = new(big.Int).Mul(z, params.P) 						//Z = z*P
	return user
}

//-----------------------------------------------------------Set Private Key--------------------------------------------------------------

func SetPrivateKey(user User) (User) {
	user.SK.z = user.USK.z
	user.SK.y = user.PSK.y	
	return user
}

//----------------------------------------------------------Set Public Key----------------------------------------------------------------

func SetPublicKey(user User) (User) {
	user.PK.X = user.PPK.X
	user.PK.Y = user.PPK.Y
	user.PK.Z = user.UPK.Z
	user.PK.d = user.PPK.d
	return user
}

//-----------------------------------------------------------Public Verify----------------------------------------------------------------

func PublicVerify (user User, params Params) () {
	var LHS = new(big.Int).Mod(new(big.Int).Mul(user.PK.d, params.P), params.q)		//If d*P == X + H1(ID, X, Y)*Ppub ?
	start := time.Now()
	var t = hash1(user.ID, user.PK.X, user.PK.Y)
	elapsed := time.Since(start)
	fmt.Println("Time taken by hash1: ",elapsed)
	var t1 = new(big.Int).Mul(t, params.Ppub)
	var t2 = new(big.Int).Add(user.PK.X, t1)
	var RHS = new(big.Int).Mod(t2, params.q)
	if(LHS.Cmp(RHS) != 0){
		panic("Public keys do no pass verification")
	}
}

//-----------------------------------------------------Re-Encryption Key Generation-------------------------------------------------------

func ReKeyGen (userI User, userJ User, params Params, rekey ReKey, L floatToint.Length) (ReKey, floatToint.Length) {
	var x, y *big.Float
	var input2 *big.Int
	a1, err := rand.Int(rand.Reader, params.q) 						//Selection of a random a1 value from Zq*
	if err != nil {
		panic(err)
	} 
	rekey.a = a1
	x = new(big.Float).SetInt(userI.SK.y)
	y = new(big.Float).SetInt(rekey.a)
	var a2 = new(big.Float).Quo(x, y)							//a1 * a2 = y

	b1, err := rand.Int(rand.Reader, params.q)						//Selection of a random b1 value from Zq*
	if err != nil {
		panic(err)
	} 
	rekey.b = b1
	x = new(big.Float).SetInt(userI.SK.z)
	y = new(big.Float).SetInt(rekey.b)
	var b2 = new(big.Float).Quo(x, y)							//b1 * b2 = z

	input2, L = floatToint.FloatToInt(a2, b2, L)
	start := time.Now()
	var v = hash2(input2)									//v = H2(a2||b2)
	elapsed := time.Since(start)
	fmt.Println("Time taken by hash2: ",elapsed)
	rekey.V = new(big.Int).Mul(v, userJ.PK.Y)						//V = v * Y
	var i = new(big.Int).Mod(new(big.Int).Mul(v, params.P), params.q)
	start1 := time.Now()
	var input1 = hash3(i)
	elapsed1 := time.Since(start1)
	fmt.Println("Time taken by hash3: ",elapsed1)
	rekey.W = new(big.Int).Xor(input1, input2)						//W = H3(v*p) xor (a2||b2)
	
	return rekey, L
}

//----------------------------------------------------------------Encryption--------------------------------------------------------------

func Encrypt(user User, m []byte, params Params, C Cipher1, C_ Cipher_) (Cipher1, Cipher_) {
	PublicVerify(user, params)
	sigma := []byte(randstring.StringWithCharset(params.l1, "01")) 				//Choosing a random string of length l1
	u, err := rand.Int(rand.Reader, params.q) 						//Selection of a random u value from Zq*
	if err != nil {
		panic(err)
	} 
	start := time.Now()
	var r = hash4(m,sigma) 									// r = H4(m,sigma)
	elapsed := time.Since(start)
	fmt.Println("Time taken by hash4: ",elapsed)
	
	C.C1 = new(big.Int).Mod(new(big.Int).Mul(r, params.P), params.q) 			//C1 = r*P
	C_.C1_ = new(big.Int).Mod(new(big.Int).Mul(u, params.P), params.q) 			//C1_ = u*P	
	
	//C3 = H5(r*Y, r*Z) xor (m//sigma)
	var Y = new(big.Int).Mod(new(big.Int).Mul(r, user.PK.Y), params.q)
	var Z = new(big.Int).Mod(new(big.Int).Mul(r, user.PK.Z), params.q)
	start1 := time.Now()
	var H = hash5(Y, Z)
	elapsed1 := time.Since(start1)
	fmt.Println("Time taken by hash5: ",elapsed1)
	var length = params.l0 + params.l1
	var hash = H[0 : length]
	var m_sigma = append(m[:], sigma[:]...)
	c3 := make([]byte, length)
	for i := 0; i < length; i++ {
		c3[i] = m_sigma[i] ^ hash[i] 
	}
	C.C3 = append(C.C3[:], c3[:]...)  	

	C.C2 = new(big.Int).Mod(new(big.Int).Mul(r, hash_(user.ID, C.C1, C_.C1_, C.C3)), params.q)     //C2 = r*H(ID,C1,C1_,C3)
	C_.C2_ = new(big.Int).Mod(new(big.Int).Mul(u, hash_(user.ID, C.C1, C_.C1_, C.C3)), params.q)   //C2_ = u*H(ID,C1,C1_,C3)

	//C4 = u + r*H6(C1,C2,C3)
	var t = new(big.Int).Mul(r, hash6(C.C1, C.C2, C.C3))
	C.C4 = new(big.Int).Mod(new(big.Int).Add(u, t), params.q)
	
	return C, C_
}

//------------------------------------------------------------Re-Encryption--------------------------------------------------------------

func ReEncrypt(userI User, userJ User, C Cipher1, D Cipher2, rekey ReKey, params Params) (Cipher2) {
	//C1_ = (C4 * P) - (H6(C1,C2,C3) * C1)
	var t1 = new(big.Int).Mul(C.C4, params.P)
	start := time.Now()
	var t2 = hash6(C.C1, C.C2, C.C3)
	elapsed := time.Since(start)
	fmt.Println("Time taken by hash6: ",elapsed)
	var t3 = new(big.Int).Mul(t2, C.C1)
	var C1_ = new(big.Int).Mod(new(big.Int).Sub(t1, t3), params.q)
	
	//C2_ = (C4 * H(ID,C1,C1_,C3)) - (H6(C1,C2,C3) * C2)
	start1 := time.Now()
	var t =  hash_(userI.ID, C.C1, C1_, C.C3)
	elapsed1 := time.Since(start1)
	fmt.Println("Time taken by hash_: ",elapsed1)
	var t4 = new(big.Int).Mul(C.C4, t)
	var t5 = new(big.Int).Mul(hash6(C.C1, C.C2, C.C3), C.C2)
	var C2_ = new(big.Int).Mod(new(big.Int).Sub(t4, t5), params.q)

	//Verification of first-level ciphertext
	//C4*P == C1_ + H6(C1,C2,C3)*C1
	var LHS = new(big.Int).Mod(new(big.Int).Mul(C.C4, params.P), params.q)
	var RHS = new(big.Int).Mod(new(big.Int).Add(C1_, t3), params.q)
	if(LHS.Cmp(RHS) != 0){
		panic("First-level ciphertext is not well formed")
	}

	//C4 * H(ID,C1,C1_,C3) == C2_ + H6(C1,C2,C3)*C2
	LHS = new(big.Int).Mod(t4, params.q)
	RHS = new(big.Int).Mod(new(big.Int).Add(C2_, t5), params.q)
	if(LHS.Cmp(RHS) != 0){
		panic("First-level ciphertext is not well formed")
	}

	D.D1 = new(big.Int).Mul(rekey.a, C.C1)								//D1 = a1*C1
	D.D2 = new(big.Int).Mul(rekey.b, C.C1)				 				//D2 = b1*C1
	D.D3 = C.C3 											//D3 = C3
	D.D4 = rekey.V 											//D4 = V
	D.D5 = rekey.W 											//D5 = W

	return D	
}

//-----------------------------------------------------------Decryption----------------------------------------------------------------

func Decrypt (user User, C Cipher1, params Params) ([]byte) {

	//C1_ = (C4 * P) - (H6(C1,C2,C3) * C1)
	var t1 = new(big.Int).Mul(C.C4, params.P)
	var t2 = hash6(C.C1, C.C2, C.C3)
	var t3 = new(big.Int).Mul(t2, C.C1)
	var C1_ = new(big.Int).Mod(new(big.Int).Sub(t1, t3), params.q)
	
	//C2_ = (C4 * H(ID,C1,C1_,C3)) - (H6(C1,C2,C3) * C2)
	var t4 = new(big.Int).Mul(C.C4, hash_(user.ID, C.C1, C1_, C.C3))
	var t5 = new(big.Int).Mul(hash6(C.C1, C.C2, C.C3), C.C2)
	var C2_ = new(big.Int).Mod(new(big.Int).Sub(t4, t5), params.q)

	//Verification of first-level ciphertext
	//C4*P == C1_ + H6(C1,C2,C3)*C1
	var LHS = new(big.Int).Mod(new(big.Int).Mul(C.C4, params.P), params.q)
	var RHS = new(big.Int).Mod(new(big.Int).Add(C1_, t3), params.q)
	if(LHS.Cmp(RHS) != 0){
		panic("First-level ciphertext is not well formed")
	}

	//C4 * H(ID,C1,C1_,C3) == C2_ + H6(C1,C2,C3)*C2
	LHS = new(big.Int).Mod(t4, params.q)
	RHS = new(big.Int).Mod(new(big.Int).Add(C2_, t5), params.q)
	if(LHS.Cmp(RHS) != 0){
		panic("First-level ciphertext is not well formed")
	}
 	
	//m||sigma = C3 xor H5(y*C1, z*C1)
	var Y = new(big.Int).Mod(new(big.Int).Mul(user.SK.y, C.C1), params.q)
	var Z = new(big.Int).Mod(new(big.Int).Mul(user.SK.z, C.C1), params.q)
	var H = hash5(Y, Z)
	var length = params.l0 + params.l1
	var hash = H[0 : length]
	m_sigma  := make([]byte, length)
	c3 := make([]byte, length)
	c3 = append(C.C3[:], c3[:]...) 
	for i := 0; i < length; i++ {
		m_sigma[i] = c3[i] ^ hash[i] 
	}
	var m = m_sigma[0 : params.l0]

	fmt.Println("\nFirst-level Ciphertext decrypted successfully\n")
	return m
}

//---------------------------------------------------------Re-Decryption---------------------------------------------------------------

func ReDecrypt (user User, C Cipher1, D Cipher2, rekey ReKey, params Params, L floatToint.Length) ([]byte) {
	var a2, b2 float64
	var t1 = new(big.Int).Mod(new(big.Int).Div(rekey.V, user.SK.y), params.q)
	var AB = new(big.Int).Xor(rekey.W, hash3(t1))						//(a2||b2) = W xor H3(V/y)
	var LHS = rekey.V
	var RHS = new(big.Int).Mul(hash2(AB), user.PK.Y)
	if(LHS.Cmp(RHS) != 0){									//if V == H2(a2||b2) * Y ?
		panic("Second-level ciphertext is not well formed")
	}
	
	//m||sigma = C3 xor H5(a2*D1, b2*D2)
	a2, b2 = floatToint.IntToFloat(AB, L)
	
	float1, err1 := strconv.ParseFloat((D.D1).String(), 64)
	if err1 != nil {
		panic(err1)
	}
	var y = new(big.Int).SetInt64(int64(math.Round(a2 * float1)))

	float2, err2 := strconv.ParseFloat((D.D2).String(), 64)
	if err2 != nil {
		panic(err2)
	}
	var z = new(big.Int).SetInt64(int64(math.Round(b2 * float2)))

	var Y = new(big.Int).Mod(y, params.q)
	var Z = new(big.Int).Mod(z, params.q)
	var H = hash5(Y, Z)
	var length = params.l0 + params.l1
	var hash = H[0 : length]
	m_sigma  := make([]byte, length)
	c3 := make([]byte, length)
	c3 = append(C.C3[:], c3[:]...) 
	for i := 0; i < length; i++ {
		m_sigma[i] = c3[i] ^ hash[i] 
	}
	var m = m_sigma[0 : params.l0]
	
	fmt.Println("\nSecond-level Ciphertext decrypted successfully\n")
	return m
}

func main() {
	var params Params
	m := []byte("Hello World, How are you.Hello World, How are you.")
	params.l0 = len(m)
	params.lID = 16
	var lambda = 14
	var userI, userJ User
	var L floatToint.Length
	var rekey ReKey
	var C Cipher1
	var C_ Cipher_
	var D Cipher2

	var s *big.Int
	params, s = Setup(params, lambda)

	userI.ID = GenerateID(params.lID)
	userJ.ID = GenerateID(params.lID)

	start1 := time.Now()
	userI = PartialKeyExtract(s, userI, params)
	elapsed1 := time.Since(start1)
	userJ = PartialKeyExtract(s, userJ, params)

	start2 := time.Now()
	userI = UserKeyGen(userI, params)
	elapsed2 := time.Since(start2)
	userJ = UserKeyGen(userJ, params)

	start3 := time.Now()
	userI = SetPrivateKey(userI)
	elapsed3 := time.Since(start3)
	userJ = SetPrivateKey(userJ)

	start4 := time.Now()
	userI = SetPublicKey(userI)
	elapsed4 := time.Since(start4)
	userJ = SetPublicKey(userJ)

	fmt.Println()
	fmt.Println("Public Key of Delegator I  : (",userI.PK.X,",", userI.PK.Y,",", userI.PK.Z,",", userI.PK.d,")")
	fmt.Println("Private Key of Delegator I : (",userI.SK.z,",", userI.SK.y,")")
	fmt.Println()
	fmt.Println("Public Key of Delegatee J  : (",userJ.PK.X,",", userJ.PK.Y,",", userJ.PK.Z,",", userJ.PK.d,")")
	fmt.Println("Private Key of Delegatee J : (",userJ.SK.z,",", userJ.SK.y,")")
	fmt.Println()

	start5 := time.Now()
	rekey, L = ReKeyGen(userI, userJ, params, rekey, L)
	elapsed5 := time.Since(start5)

	start6 := time.Now()
	C, C_ = Encrypt(userI, m, params, C, C_)
	elapsed6 := time.Since(start6)

	start7 := time.Now()
	D = ReEncrypt(userI, userJ, C, D, rekey, params)
	elapsed7 := time.Since(start7)

	start8 := time.Now()
	var m1 = Decrypt(userI, C, params)
	elapsed8 := time.Since(start8)

	fmt.Println("Re-encryption Key : (",rekey.a,",",rekey.b,",",rekey.V,",",rekey.W,")")

	start9 := time.Now()
	var m2 = ReDecrypt(userJ, C, D, rekey, params, L)
	elapsed9 := time.Since(start9)

	fmt.Println()
	fmt.Println("Time Taken for Partial Key Extraction:  ", elapsed1)
	fmt.Println("Time Taken for User Key Generation:     ", elapsed2)
	fmt.Println("Time Taken for SetPrivateKey: 	     	", elapsed3)
	fmt.Println("Time Taken for SetPublicKey: 	     	", elapsed4)
	fmt.Println("Time Taken for First level encryption:  ", elapsed6)
	fmt.Println("Time Taken for First level decryption:  ", elapsed8)
	fmt.Println("Time Taken for ReKey Generation:        ", elapsed5)
	fmt.Println("Time Taken for Second level encryption: ", elapsed7)
	fmt.Println("Time Taken for Second level decryption: ", elapsed9)

	fmt.Println()
	fmt.Println("Message encrypted     : ",string(m[:]))
	fmt.Println("Message decrypted I   : ",string(m1[:]))
	fmt.Println("Message decrypted II  : ",string(m2[:]))
}
