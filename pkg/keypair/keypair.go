package keypair

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/sign/anon"
)

func ScalarToString(scalar kyber.Scalar) string {
	data, _ := scalar.MarshalBinary()
	return base64.StdEncoding.EncodeToString(data)
}

func PointsToStrings(points anon.Set) string {
	out := make([]string, len(points))
	for i, point := range points {
		data, _ := point.MarshalBinary()
		out[i] = base64.StdEncoding.EncodeToString(data)
	}
	return strings.Join(out, ",")
}

func StringToScalar(m string) (kyber.Scalar, error) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	scalar := suite.Scalar()
	data, err := base64.StdEncoding.DecodeString(m)

	if err != nil {
		return nil, err
	}

	err = scalar.UnmarshalBinary(data)

	if err != nil {
		return nil, err
	}

	return scalar, nil
}

func StringsToPoints(ms string) (anon.Set, error) {

	msgs := strings.Split(ms, ",")

	set := make(anon.Set, len(msgs))
	suite := edwards25519.NewBlakeSHA256Ed25519()

	for i, msg := range msgs {

		p := suite.Point()
		data, err := base64.StdEncoding.DecodeString(msg)

		if err != nil {
			return nil, err
		}

		err = p.UnmarshalBinary(data)

		if err != nil {
			return nil, err
		}

		set[i] = p
	}
	return set, nil
}

type KeyPair struct {
	Pubs anon.Set     `json:"pubs"`
	Priv kyber.Scalar `json:"priv"`
	Idx  int          `json:"idx"`
}

func (t *KeyPair) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Pubs string `json:"pubs"`
		Priv string `json:"priv"`
		Idx  int    `json:"idx"`
	}{
		Pubs: PointsToStrings(t.Pubs),
		Priv: ScalarToString(t.Priv),
		Idx:  t.Idx,
	})
}

func (t *KeyPair) UnmarshalJSON(data []byte) error {

	var s struct {
		Pubs string `json:"pubs"`
		Priv string `json:"priv"`
		Idx  int    `json:"idx"`
	}

	err := json.Unmarshal(data, &s)
	var _ = err

	priv, err := StringToScalar(s.Priv)

	if err != nil {
		return err
	}

	pubs, err := StringsToPoints(s.Pubs)

	if err != nil {
		return err
	}

	*t = KeyPair{
		Pubs: pubs,
		Priv: priv,
		Idx:  s.Idx,
	}

	return nil
}
