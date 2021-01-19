package dhpals

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
)

// Find small factors of the cofactor
func findSmallOrders(cofactor *big.Int) ([]*big.Int, error) {
	var smallfactors []*big.Int
	j := new(big.Int).Set(cofactor)
	smallrange := new(big.Int).SetInt64(1 << 16)

	for i := big.NewInt(2); i.Cmp(smallrange) < 0; i.Add(i, Big1) {
		if divides(i, j) {
			smallfactors = append(smallfactors, new(big.Int).Set(i))
			for divides(i, j) {
				j.Div(j, i)
			}
		}
		if i.Cmp(j) >= 0 {
			break
		}
	}

	if len(smallfactors) == 0 {
		return nil, fmt.Errorf("Couldn't find factors for %d", cofactor)
	}
	return smallfactors, nil
}

// Find h = rand(1, p)^((p-1)/r) mod p, h != 1
func findElementOfSmallOrder(p, order *big.Int) (*big.Int, error) {
	h := new(big.Int).Set(Big1)
	neworder := new(big.Int).Div(new(big.Int).Sub(p, Big1), order)
	for h.Cmp(Big1) == 0 {
		random, err := rand.Int(rand.Reader, p)
		if err != nil {
			return nil, err
		}
		if random.Cmp(Big0) == 0 {
			random.Set(Big1)
		}
		h = new(big.Int).Exp(random, neworder, p)
	}
	return h, nil
}

// Find x: newt = MAC(h^x mod p, m), t == newt
func bruteSecretModOrder(order, h, p *big.Int, t []byte) (*big.Int, error) {
	if new(big.Int).Exp(h, order, p).Cmp(Big1) != 0 {
		err := fmt.Errorf("There is no order %d for h %d", order, h)
		return nil, err
	}
	for i := big.NewInt(0); i.Cmp(order) < 0; i.Add(i, Big1) {
		x := new(big.Int).Exp(h, i, p)
		tB := mixKey(x.Bytes())
		if bytes.Equal(tB, t) {
			return i, nil
		}
	}
	err := fmt.Errorf("Couldn't find appropriate value with brute force with order %d", order)
	return nil, err
}

func runDHSmallSubgroupAttack(p, cofactor *big.Int, dh func(*big.Int) []byte) (priv *big.Int) {
	j, err := findSmallOrders(cofactor)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	var x, r []*big.Int
	q := new(big.Int).Div(p, cofactor)
	mod := new(big.Int).Set(Big0)

	for _, order := range j {
		h, err := findElementOfSmallOrder(p, order)
		if err != nil {
			fmt.Println(err)
			return nil
		}
		// K := h^x mod p, t := MAC(K, m)
		t := dh(h)
		bmodr, err := bruteSecretModOrder(order, h, p, t)
		if err != nil {
			fmt.Println(err)
			return nil
		}
		x = append(x, bmodr)
		r = append(r, order)

		// Check (r1*r2*...*rn) > q
		mod.Mul(mod, order)
		if mod.Cmp(q) > 0 {
			break
		}
	}
	priv, _, err = crt(x, r)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return
}

// from https://arxiv.org/pdf/0812.0789.pdf: d≈log2√(b−a) + log2log2√(b−a)−2
func findK(a, b *big.Int) *big.Int {
	distance := new(big.Int).Sub(b, a)
	logdis := math.Log2(float64(distance.Sqrt(distance).Uint64()))
	jumpsize := logdis + math.Log2(logdis) - 2
	return new(big.Int).SetUint64(uint64(jumpsize + 1))
}

// N is then derived from f: 4 multiplied by all possible outputs of f
func findN(k, p *big.Int) *big.Int {
	N, i := new(big.Int).Set(Big0), new(big.Int).Set(Big0)
	for ; i.Cmp(k) < 0; i.Add(i, Big1) {
		N.Add(N, fy(i, k, p))
	}
	return N.Mul(big.NewInt(4), N.Div(N, k))
}

// f(y) = 2^(y mod k)
func fy(y, k, p *big.Int) *big.Int {
	return new(big.Int).Exp(Big2, new(big.Int).Mod(y, k), p)
}

func tameKangaroo(p, g, b, k *big.Int) (xt, yt *big.Int, err error) {
	N := findN(k, p)
	xt = new(big.Int).Set(Big0)
	yt = new(big.Int).Exp(g, b, p)

	for i := big.NewInt(0); i.Cmp(N) < 0; i.Add(i, Big1) {
		fy := fy(yt, k, p)
		xt.Add(xt, fy)
		yt.Mul(yt, new(big.Int).Exp(g, fy, p))
		yt.Mod(yt, p)
	}

	expectedValue := new(big.Int).Exp(g, new(big.Int).Add(b, xt), p)
	if yt.Cmp(expectedValue) != 0 {
		return nil, nil, fmt.Errorf("Expected value wasn't achived with p %d", p)
	}
	return xt, yt, nil
}

// catchKangaroo implements Pollard's kangaroo algorithm.
func catchKangaroo(p, g, y, a, b *big.Int) (m *big.Int, err error) {
	k := findK(a, b)

	xt, yt, err := tameKangaroo(p, g, b, k)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	xw := new(big.Int).Set(Big0)
	yw := new(big.Int).Set(y)

	dif := new(big.Int).Add(xt, new(big.Int).Sub(b, a))
	for xw.Cmp(dif) < 0 {
		fy := fy(yw, k, p)
		xw.Add(xw, fy)
		yw.Mul(yw, new(big.Int).Exp(g, fy, p))
		yw.Mod(yw, p)

		if yw.Cmp(yt) == 0 {
			value := new(big.Int).Add(b, new(big.Int).Sub(xt, xw))
			if y.Cmp(new(big.Int).Exp(g, value, p)) != 0 {
				return nil, fmt.Errorf("Wild one wasn't catched")
			}
			return value, nil
		}
	}
	return nil, fmt.Errorf("value wasn't found")
}

func runDHKangarooAttack(p, g, q, cofactor *big.Int, dh func(*big.Int) []byte, getPublicKey func() *big.Int) (priv *big.Int) {
	j, err := findSmallOrders(cofactor)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	var x, r []*big.Int

	for _, order := range j {
		h, err := findElementOfSmallOrder(p, order)
		if err != nil {
			fmt.Println(err)
			return nil
		}
		t := dh(h)
		br, err := bruteSecretModOrder(order, h, p, t)
		if err != nil {
			fmt.Println(err)
			return nil
		}
		x = append(x, br)
		r = append(r, order)
	}

	// x = n mod r, r = (r1*r2*...*rn)
	n, mod, err := crt(x, r)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	fmt.Println("founded n: ", n)

	y := getPublicKey()

	// y' = y * g^-n = g^(m*r)
	ynew := new(big.Int).Mul(y, new(big.Int).Exp(g, new(big.Int).Neg(n), p))
	ynew = ynew.Mod(ynew, p)

	// g' = g^r
	gnew := new(big.Int).Exp(g, mod, p)

	// rough bound for m: [0, (q-1)/r]
	leftbound := big.NewInt(0)
	rightbound := new(big.Int).Div(new(big.Int).Sub(q, Big1), mod)

	m, err := catchKangaroo(p, gnew, ynew, leftbound, rightbound)

	if err != nil {
		fmt.Println(err)
		return nil
	}

	// x = n + m*r
	priv = new(big.Int).Add(n, new(big.Int).Mul(m, mod))
	return
}
