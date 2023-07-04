package keypair

import (
	"encoding/base64"
	"encoding/json"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/sign/anon"
)

func ScalarToString(scalar kyber.Scalar) string {
	data, _ := scalar.MarshalBinary()
	return base64.StdEncoding.EncodeToString(data)
}

func PointsToStrings(points anon.Set) []string {
	out := make([]string, len(points))
	for i, point := range points {
		data, _ := point.MarshalBinary()
		out[i] = base64.StdEncoding.EncodeToString(data)
	}
	return out
}

func StringToScalar(msg string) kyber.Scalar {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	scalar := suite.Scalar()
	data, _ := base64.StdEncoding.DecodeString(msg)
	_ = scalar.UnmarshalBinary(data)
	return scalar
}

func StringsToPoints(msgs []string) anon.Set {
	set := make(anon.Set, len(msgs))
	suite := edwards25519.NewBlakeSHA256Ed25519()
	for i, msg := range msgs {
		p := suite.Point()
		data, _ := base64.StdEncoding.DecodeString(msg)
		_ = p.UnmarshalBinary(data)
		set[i] = p
	}
	return set
}

type KeyPair struct {
	Pubs anon.Set     `json:"pubs"`
	Priv kyber.Scalar `json:"priv"`
	Idx  int          `json:"idx"`
}

func (t *KeyPair) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Pubs []string `json:"pubs"`
		Priv string   `json:"priv"`
		Idx  int      `json:"idx"`
	}{
		Pubs: PointsToStrings(t.Pubs),
		Priv: ScalarToString(t.Priv),
		Idx:  t.Idx,
	})
}

func (t *KeyPair) UnmarshalJSON(data []byte) error {

	var s struct {
		Pubs []string `json:"pubs"`
		Priv string   `json:"priv"`
		Idx  int      `json:"idx"`
	}

	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}

	*t = KeyPair{
		Pubs: StringsToPoints(s.Pubs),
		Priv: StringToScalar(s.Priv),
		Idx:  s.Idx,
	}

	return nil
}
