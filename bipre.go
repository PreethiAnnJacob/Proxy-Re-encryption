package main

import (
	"fmt"
	"math/big"
	"crypto/rand"
	"randstring"
	"crypto/sha512"
	"time"
)

//User Structure comprising secret key and public key
type User struct {
	sk *big.Int
	pk *big.Int
}

type Cipher1 struct{
	C1 *big.Int
	C2 *big.Int
	C3 []byte
	C4 *big.Int
}

type Cipher2 struct{
	D1 *big.Int
	D2 []byte
}

type Params struct{
	p *big.Int
	q *big.Int
	g *big.Int
	lm int
}

type Cipher_ struct{
	C1_ *big.Int
	C2_ *big.Int
}

type Valid struct{
	r *big.Int
	u *big.Int
}

//--------------------------------------------------------------Hash Functions--------------------------------------------------------------

//---------------------------------------------------H1: Maps to an element in cyclic group-------------------------------------------------

func hash1 (m []byte, w []byte) (*big.Int){
	h := sha512.New()
	if _, err := h.Write(m); err != nil {
		panic(err)
	}
	if _, err := h.Write(w); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	r := new(big.Int)
	r.SetBytes(h1)
	return r
}

//---------------------------------------------------H2: Maps to an element in cyclic group-------------------------------------------------

func hash2 (pkI *big.Int, C1 *big.Int) (*big.Int){
	h := sha512.New()
	if _, err := h.Write(pkI.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(C1.Bytes()); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	r := new(big.Int)
	r.SetBytes(h1)
	return r
}

//----------------------------------------------------------H3: Maps to a string------------------------------------------------------------

func hash3 (G *big.Int) ([]byte){
	h := sha512.New()
	if _, err := h.Write(G.Bytes()); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	return h1
}

//---------------------------------------------------H4: Maps to an element in cyclic group-------------------------------------------------

func hash4 (C1 *big.Int, C2 *big.Int, C1_ *big.Int, C2_ *big.Int, C3 []byte, pkI *big.Int) (*big.Int){
	h := sha512.New()
	if _, err := h.Write(C1.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(C2.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(C1_.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(C2_.Bytes()); err != nil {
		panic(err)
	}
	if _, err := h.Write(C3); err != nil {
		panic(err)
	}
	if _, err := h.Write(pkI.Bytes()); err != nil {
		panic(err)
	}
	h1 := h.Sum(nil)
	r := new(big.Int)
	r.SetBytes(h1)
	return r
}

//----------------------------------------------------------------Setup-------------------------------------------------------------------

func Setup (params Params) (Params) {
	params.p = big.NewInt(458669)
	params.q = big.NewInt(16381)
	params.g = big.NewInt(16380)
	
	return params
}

//-----------------------------------------------------------Key Generation----------------------------------------------------------------

func KeyGen (user User, params Params) (User){
	sk , err := rand.Int(rand.Reader, params.q) 					//Secret Key calculation : A random value x within Zq*
	if err != nil {
		panic(err)
	}
	user.sk = sk
	user.pk = new(big.Int).Exp(params.g, user.sk, params.q)				//Public key calculation : g^x
	return user
}

//----------------------------------------------------Re-Encryption Key Generation----------------------------------------------------------

func ReKeyGen (userI User, userJ User,params Params) (*big.Int){	
	var skInv = new(big.Int).ModInverse(userI.sk, params.q)
	var rekey = new(big.Int).Mul(userJ.sk, skInv)					//rekey(i->j) = xj/xi
	return rekey
}

//-----------------------------------------------------------Encryption--------------------------------------------------------------------

func Encrypt (m []byte, user User, params Params, C Cipher1, C_ Cipher_, V Valid) (Cipher1, Cipher_,  Valid){
	var l1 = 0
	if(params.lm < 64){
		l1 = 64 - params.lm
	}

	u, err := rand.Int(rand.Reader, params.q) 					//Selection of a random u value
	if err != nil {
		panic(err)
	}
	V.u = u

	const charset = "01"
	w := []byte(randstring.StringWithCharset(l1, charset)) 				//Generating random padding string
	V.r = new(big.Int).Mod(hash1(m,w), params.q)					// r = H1(m,w)
	//fmt.Println(user.pk, V.r)
	
	C.C1 = new(big.Int).Exp(user.pk, V.r, params.q) 				// C1 = pkI^r
	var t = hash2(user.pk, C.C1)
	C_.C1_ = new(big.Int).Exp(t, V.r, params.q)					// C1_ = H2(pkI, C1)^r
	
	s, err := rand.Int(rand.Reader, params.q) 					//Selection of a random u value
	if err != nil {
		panic(err)
	}
	C.C2 = new(big.Int).Exp(user.pk, s, params.q) 					// C2 = pkI^s
	C_.C2_ = new(big.Int).Exp(hash2(user.pk, C.C1), s, params.q) 			// C2_ = H2(pkI, C1)^s

	var mw = append(m[:], w[:]...)
	//var z = new(big.Int).Exp(params.g, V.r, params.q)
	//fmt.Println("Z", z)
	var hash = hash3(new(big.Int).Exp(params.g, V.r, params.q))
	var c3 [64]byte
	for i := 0; i < 64; i++ {
		c3[i] = mw[i] ^ hash[i] 						// C3 = m||w xor H3(g^r)
	}
	C.C3 = append(C.C3[:], c3[:]...)

	h := hash4(C.C1, C.C2, C_.C1_, C_.C2_, C.C3, user.pk) 				// h = H4(C1, C2, C1_, C2_, C3, pkI)
	var t1 = new(big.Int).Mul(V.u, h)
	var t2 = new(big.Int).Add(V.r, t1)

	C.C4 = new(big.Int).Mod(t2, params.q) 						// C4 = (r + uh) mod q

	//fmt.Println(C.C1, C.C2, C.C3, C.C4, C_.C1_, C_.C2_, V.r, V.u)
	return C, C_, V
}

//---------------------------------------------------------Validation Check------------------------------------------------------------

func Validity(C Cipher1, C_ Cipher_, user User, V Valid, params Params) (*big.Int){
	h := hash4(C.C1, C.C2, C_.C1_, C_.C2_, C.C3, user.pk) 				// h = H4(C1, C2, C1_, C2_, C3, pkI)
	var t1 = new(big.Int).Mul(V.u, h)
	var t2 = new(big.Int).Add(V.r, t1)
	var v = new(big.Int).Mod(t2, params.q) 						//v = (r + uh) mod q
	return v
}

//------------------------------------------------------------Re-Encrypt----------------------------------------------------------------

func ReEncrypt(C Cipher1, D Cipher2, C_ Cipher_, rekey *big.Int, user User, V Valid, params Params ) (Cipher2){
	var v = Validity(C, C_, user, V, params)
	if(v.Cmp(C.C4) == 0){
		D.D1 = new(big.Int).Exp(C.C1, rekey, nil)				// D1 = C1^rekey
		D.D2 = append(D.D2[:], C.C3[:]...)					// D2 = C3
	}
	//fmt.Println()
	//fmt.Println(D.D1, D.D2)
	return D
}

//-------------------------------------------------------------Decrypt-----------------------------------------------------------------

func Decrypt(C Cipher1, C_ Cipher_, user User, V Valid, params Params) ([]byte) {
	//var v = Validity(C, C1_, C2_, pkI, u, r, q)
	//if(bytes.Compare(v, C.C4) == 0){
		var skInv = new(big.Int).ModInverse(user.sk, params.q)					// Inverse secret key xi^-1
		var T = (new(big.Int).Exp(C.C1, skInv, params.q)) 					// T=C1^xi^-1
		var hash = hash3(T)
		
		var mw [64]byte
		for i := 0; i < 64; i++ {
			mw[i] = hash[i] ^ C.C3[i] 							//  m||w = H3(T) xor C3
		}		
				
		var m = mw[:params.lm]
		//var w = mw[length + 1:]								//Slice to m and w

		//if(bytes.Compare(C.C1, (new(big.Int).Exp(pkI,hash1(m,w),q)).Bytes()) == 0){
			return m 									//if c1= H1(m,w) return m else null
		//}
	//}
	//return nil
}

//-------------------------------------------------------------Re-Decrypt-----------------------------------------------------------------

func ReDecrypt(D Cipher2, user User, params Params) ([]byte) {
	var skInv = new(big.Int).ModInverse(user.sk, params.q)
	var T = new(big.Int).Exp(D.D1, skInv, params.q)							//T=D1^xj^-1
	var hash = hash3(T)
	
	var mw [64]byte
	for i := 0; i < 64; i++ {
		mw[i] = hash[i] ^ D.D2[i] 								//  m||w = H3(T) xor D2
	}
	var m = mw[:params.lm]
	//var w = mw[length+1:] 									//Slice to m and w
	//if (bytes.Compare(D.D1, (new(big.Int).Exp(pkJ,hash1(m,w),q)).Bytes()) == 0){
		return m 										//H1(m,w)=D1 then return m else null
	//}	
	//return nil
}


func main() {
	var params Params
	m := []byte("Hello World, How are you.")
	params.lm = len(m)
	var userI, userJ User
	var rekey *big.Int
	var C Cipher1
	var C_ Cipher_
	var V Valid
	var D Cipher2
	var m1 []byte	
	var m2 []byte
	
	params = Setup(params)	

	start1 := time.Now()
	userI = KeyGen(userI, params)
	elapsed1 := time.Since(start1)
	userJ = KeyGen(userJ, params)

	start2 := time.Now()
	rekey = ReKeyGen(userI, userJ, params)
	elapsed2 := time.Since(start2)
	
	start3 := time.Now()	
	C, C_, V = Encrypt(m, userI, params, C, C_, V)
	elapsed3 := time.Since(start3)

	start4 := time.Now()
	D = ReEncrypt(C, D, C_, rekey, userI, V, params)
	elapsed4 := time.Since(start4)

	start5 := time.Now()
	m1 = Decrypt(C, C_, userI, V, params)
	elapsed5 := time.Since(start5)

	start6 := time.Now()	
	m2 = ReDecrypt(D, userJ, params)
	elapsed6 := time.Since(start6)

	fmt.Println()
	fmt.Println("Time Taken for Key Generation			:  ", elapsed1)
	fmt.Println("Time Taken for Re-encryption Key Generation	:  ", elapsed2)
	fmt.Println("Time Taken for Encryption			:  ", elapsed3)
	fmt.Println("Time Taken for Re-encryption			:  ", elapsed4)
	fmt.Println("Time Taken for Decryption			:  ", elapsed5)
	fmt.Println("Time Taken for Re-decyption			:  ", elapsed6)
	fmt.Println()

	fmt.Println()
	fmt.Println("Message encrypted     : ",string(m[:]))
	fmt.Println("Message decrypted I   : ",string(m1[:]))
	fmt.Println("Message decrypted II  : ",string(m2[:]))
}

