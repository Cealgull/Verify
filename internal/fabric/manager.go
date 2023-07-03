package fabric

import (
	"github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
)

type FabricManager struct {
	c *msp.Client
}

type FabricOptions struct {
	cahost string
	org    string
	conf   core.ConfigProvider
}

type Option func(opts *FabricOptions) error

func WithCAHost(host string) Option {
	return func(opts *FabricOptions) error {
		opts.cahost = host
		return nil
	}
}

func WithConfiguration(conf string) Option {
	return func(opts *FabricOptions) error {
		opts.conf = config.FromFile(conf)
		return nil
	}
}

func WithOrg(org string) Option {
	return func(opts *FabricOptions) error {
		opts.org = org
		return nil
	}
}

func New(opts ...Option) (*FabricManager, error) {
	option := FabricOptions{}
	for _, f := range opts {
		err := f(&option)
		if err != nil {
			panic(err)
		}
	}

	var err error
	var sdk *fabsdk.FabricSDK
	var c *msp.Client

	sdk, err = fabsdk.New(option.conf)
	if err != nil {
		return nil, err
	}

	ctx := sdk.Context()

	c, err = msp.New(ctx,
		msp.WithOrg(
			option.org,
		),
		msp.WithCAInstance(
			option.cahost,
		))

	if err != nil {
		return nil, err
	}

	m := FabricManager{c}
	return &m, nil
}

func (m *FabricManager) Register(id string, secret string) error {
	_, err := m.c.Register(&msp.RegistrationRequest{
		Name:   id,
		Secret: secret,
	})
	return err
}
