module github.com/hyperledger/fabric-sdk-go

go 1.15

require (
	github.com/Knetic/govaluate v3.0.0+incompatible
	github.com/cloudflare/cfssl v1.4.1
	github.com/ethereum/go-ethereum v1.9.0
	github.com/go-kit/kit v0.8.0
	github.com/golang/mock v1.4.3
	github.com/golang/protobuf v1.5.2
	github.com/hyperledger/fabric-config v0.0.5
	github.com/hyperledger/fabric-lib-go v1.0.0
	github.com/hyperledger/fabric-protos-go v0.0.0-20200707132912-fee30f3ccd23
	github.com/miekg/pkcs11 v1.0.3
	github.com/mitchellh/mapstructure v1.3.2
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7
	github.com/pkg/errors v0.9.1
	github.com/privacy-protection/common v1.9.1
	github.com/privacy-protection/cp-abe v1.9.1
	github.com/privacy-protection/hybrid-encryption v0.0.0
	github.com/privacy-protection/kp-abe v1.8.0
	github.com/prometheus/client_golang v1.1.0
	github.com/spf13/cast v1.3.1
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.7.0
	github.com/sykesm/zap-logfmt v0.0.4
	go.uber.org/zap v1.13.0
	golang.org/x/crypto v0.0.0-20211215153901-e495a2d5b3d3
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2
	golang.org/x/tools v0.0.0-20200103221440-774c71fcf114
	google.golang.org/grpc v1.29.1
	gopkg.in/yaml.v2 v2.3.0

)

replace (
	github.com/privacy-protection/common => ../common
	github.com/privacy-protection/cp-abe => ../cp-abe
	github.com/privacy-protection/hybrid-encryption => ../hybrid-encryption
	github.com/privacy-protection/kp-abe => ../kp-abe
)
