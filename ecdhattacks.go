package dhpals

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/dnkolegov/dhpals/elliptic"
	"github.com/dnkolegov/dhpals/x128"
)

func findPoint(r *big.Int, curve elliptic.Curve) (*big.Int, *big.Int, error) {
	x, y := new(big.Int), new(big.Int)
	order := new(big.Int).Div(curve.Params().N, r).Bytes()
	i := new(big.Int).Set(Big1)

	for ; i.Cmp(r) <= 0; i.Add(i, Big1) {
		x, y = elliptic.GeneratePoint(curve)
		x, y = curve.ScalarMult(x, y, order)
		if x.Cmp(Big0) != 0 && y.Cmp(Big0) != 0 {
			return x, y, nil
		}
	}
	return nil, nil, fmt.Errorf("Couldn't find a point with order %d on the curve %s", r, curve.Params().Name)
}

func bruteECDH(x, y, order *big.Int, h []byte, curve elliptic.Curve) (*big.Int, error) {
	testx, testy := curve.ScalarMult(x, y, order.Bytes())
	if testx.Cmp(Big0) != 0 && testy.Cmp(Big0) != 0 {
		return nil, fmt.Errorf("There is no order %d for point on the curve %s", order, curve.Params().Name)
	}
	i := new(big.Int).Set(Big1)
	var tempx, tempy *big.Int
	for ; i.Cmp(order) <= 0; i.Add(i, Big1) {
		tempx, tempy = curve.ScalarMult(x, y, i.Bytes())
		k := append(tempx.Bytes(), tempy.Bytes()...)
		temph := mixKey(k)
		if bytes.Equal(temph, h) {
			return i, nil
		}
	}
	return nil, fmt.Errorf("Couldn't find appropriate value with brute force with order %d on the curve %s", order, curve.Params().Name)

}

func appendUnique(r, b []*big.Int, order, key *big.Int) ([]*big.Int, []*big.Int) {
	for _, v := range r {
		if v.Cmp(order) == 0 {
			return r, b
		}
	}
	r = append(r, order)
	b = append(b, key)
	return r, b

}

func runECDHInvalidCurveAttack(ecdh func(x, y *big.Int) []byte) (priv *big.Int) {
	curves := []elliptic.Curve{elliptic.P128(), elliptic.P128V1(), elliptic.P128V2(), elliptic.P128V3()}

	var b, r []*big.Int

	for _, curve := range curves {
		j, err := findSmallOrders(curve.Params().N)
		if err != nil {
			fmt.Println(err)
			continue
		}
		for _, order := range j {
			x, y, err := findPoint(order, curve)
			if err != nil {
				fmt.Println(err)
				continue
			}
			h := ecdh(x, y)

			tb, err := bruteECDH(x, y, order, h, curve)
			if err != nil {
				fmt.Println(err)
				return nil
			}
			r, b = appendUnique(r, b, order, tb)
		}
	}
	priv, _, err := crt(b, r)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return
}

func runECDHSmallSubgroupAttack(curve elliptic.Curve, ecdh func(x, y *big.Int) []byte) (priv *big.Int) {
	panic("not implemented")
	return
}

func runECDHTwistAttack(ecdh func(x *big.Int) []byte, getPublicKey func() (*big.Int, *big.Int), privateKeyOracle func(*big.Int) *big.Int) (priv *big.Int) {
	panic("not implemented")
	return
}

type twistPoint struct {
	order *big.Int
	point *big.Int
}

// findAllPointsOfPrimeOrderOnX128 finds a point with a specified order for u^3 + A*u^2 + u in GF(p).
func findAllPointsOfPrimeOrderOnX128() (points []twistPoint) {
	// It is known, that both curves contain 2*p+2 points: |E| + |T| = 2*p + 2
	panic("not implemented")
	x128.ScalarBaseMult(big.NewInt(1).Bytes())
	return
}

// catchKangarooOnCurve implements Pollard's kangaroo algorithm on a curve.
func catchKangarooOnCurve(curve elliptic.Curve, bx, by, x, y, a, b *big.Int) (m *big.Int, err error) {
	// k is calculated based on a formula in this paper: https://arxiv.org/pdf/0812.0789.pdf
	panic("not implemented")
	return
}
