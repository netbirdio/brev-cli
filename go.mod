module github.com/brevdev/brev-cli

go 1.26.0

toolchain go1.26.7

require (
	buf.build/gen/go/brevdev/devplane/connectrpc/go v1.21.0-20260915224432-6a5d0c858507.1
	buf.build/gen/go/brevdev/devplane/protocolbuffers/go v1.36.12-20260915224432-6a5d0c858507.2
	connectrpc.com/connect v1.21.0
	github.com/NVIDIA/go-nvml v0.13.0-1
	github.com/alessio/shellescape v1.4.1
	github.com/brevdev/parse v0.0.11
	github.com/briandowns/spinner v1.16.0
	github.com/cenkalti/backoff/v4 v4.3.0
	github.com/fatih/color v1.13.0
	github.com/getsentry/sentry-go v0.14.0
	github.com/gin-gonic/gin v1.10.0
	github.com/go-git/go-git/v5 v5.19.2
	github.com/go-resty/resty/v2 v2.17.0
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/go-cmp v0.7.0
	github.com/google/huproxy v0.0.0-20210816191033-a131ee126ce3
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-version v1.7.0
	github.com/jarcoal/httpmock v1.0.8
	github.com/jinzhu/copier v0.4.0
	github.com/kevinburke/ssh_config v1.4.0
	github.com/manifoldco/promptui v0.9.0
	github.com/netbirdio/netbird v0.81.0-canary.pr-8098.1.0.20261008142856-01d828d732e3
	github.com/pkg/browser v0.0.0-20210911075715-681adbf594b8
	github.com/pkg/errors v0.9.1
	github.com/posthog/posthog-go v1.10.0
	github.com/robfig/cron/v3 v3.0.1
	github.com/samber/lo v1.33.0
	github.com/samber/mo v1.5.1
	github.com/schollz/progressbar/v3 v3.9.0
	github.com/sevlyar/go-daemon v0.1.5
	github.com/sirupsen/logrus v1.9.4
	github.com/spf13/afero v1.15.0
	github.com/spf13/cobra v1.10.2
	github.com/spf13/viper v1.21.0
	github.com/stretchr/testify v1.12.1
	github.com/tidwall/gjson v1.14.0
	github.com/tweekmonster/luser v0.0.0-20161003172636-3fa38070dbd7
	github.com/wk8/go-ordered-map/v2 v2.0.0
	github.com/writeas/go-strip-markdown v2.0.1+incompatible
	golang.org/x/crypto v0.55.0
	golang.org/x/text v0.41.0
	k8s.io/cli-runtime v0.31.1
)

require (
	buf.build/gen/go/brevdev/protoc-gen-gotag/protocolbuffers/go v1.36.12-20220906235457-8b4922735da5.2 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	cunicu.li/go-rosenpass v0.5.42 // indirect
	dario.cat/mergo v1.0.2 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20250102033503-faa5f7b0171c // indirect
	github.com/DeRuina/timberjack v1.4.2 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/ProtonMail/go-crypto v1.3.0 // indirect
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/aws/aws-sdk-go-v2 v1.38.3 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.31.6 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.18.10 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/route53 v1.42.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.29.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.34.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.38.2 // indirect
	github.com/aws/smithy-go v1.23.0 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/bytedance/sonic v1.11.6 // indirect
	github.com/bytedance/sonic/loader v0.1.1 // indirect
	github.com/caddyserver/certmagic v0.21.3 // indirect
	github.com/caddyserver/zerossl v0.1.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cilium/ebpf v0.19.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/cloudwego/base64x v0.1.4 // indirect
	github.com/cloudwego/iasm v0.2.0 // indirect
	github.com/coder/websocket v1.8.14 // indirect
	github.com/coreos/go-iptables v0.7.0 // indirect
	github.com/creack/pty v1.1.24 // indirect
	github.com/cyphar/filepath-securejoin v0.6.1 // indirect
	github.com/ebitengine/purego v0.9.1 // indirect
	github.com/emicklei/go-restful/v3 v3.11.0 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.1 // indirect
	github.com/gabriel-vasile/mimetype v1.4.3 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/gliderlabs/ssh v0.3.8 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.9.0 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-openapi/swag/jsonname v0.26.1 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.20.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/gnostic-models v0.6.8 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/google/nftables v0.3.0 // indirect
	github.com/gopacket/gopacket v1.4.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.26.3 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/huin/goupnp v1.2.0 // indirect
	github.com/jackpal/go-nat-pmp v1.0.2 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/klauspost/compress v1.18.7 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/koron/go-ssdp v0.0.4 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/libdns/libdns v0.2.2 // indirect
	github.com/libdns/route53 v1.5.0 // indirect
	github.com/libp2p/go-netroute v0.4.0 // indirect
	github.com/lrh3321/ipset-go v0.0.0-20250619021614-54a0a98ace81 // indirect
	github.com/lufia/plan9stats v0.0.0-20240513124658-fba389f38bae // indirect
	github.com/mdlayher/genetlink v1.3.2 // indirect
	github.com/mdlayher/netlink v1.7.3-0.20250113171957-fbb4dce95f42 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/mholt/acmez/v2 v2.0.1 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/mitchellh/hashstructure/v2 v2.0.2 // indirect
	github.com/moby/term v0.5.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/netbirdio/go-nat v0.0.0-20260821095157-6b2c8c5c74e8 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/petermattis/goid v0.0.0-20250303134427-723919f7f203 // indirect
	github.com/pion/dtls/v2 v2.2.10 // indirect
	github.com/pion/dtls/v3 v3.0.9 // indirect
	github.com/pion/ice/v4 v4.0.0-00010101000000-000000000000 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/mdns/v2 v2.0.7 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/stun/v2 v2.0.0 // indirect
	github.com/pion/stun/v3 v3.1.0 // indirect
	github.com/pion/transport/v2 v2.2.4 // indirect
	github.com/pion/transport/v3 v3.1.1 // indirect
	github.com/pion/turn/v3 v3.0.1 // indirect
	github.com/pion/turn/v4 v4.1.1 // indirect
	github.com/pjbgf/sha1cd v0.6.0 // indirect
	github.com/pkg/sftp v1.13.9 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.67.5 // indirect
	github.com/prometheus/procfs v0.19.2 // indirect
	github.com/quic-go/quic-go v0.62.0 // indirect
	github.com/sagikazarmark/locafero v0.11.0 // indirect
	github.com/sergi/go-diff v1.4.0 // indirect
	github.com/shirou/gopsutil/v4 v4.25.8 // indirect
	github.com/skeema/knownhosts v1.3.2 // indirect
	github.com/skratchdot/open-golang v0.0.0-20200116055534-eef842397966 // indirect
	github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/things-go/go-socks5 v0.0.4 // indirect
	github.com/ti-mo/conntrack v0.5.1 // indirect
	github.com/ti-mo/netfilter v0.5.2 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/tklauser/go-sysconf v0.3.15 // indirect
	github.com/tklauser/numcpus v0.10.0 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.2.12 // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	github.com/zcalusic/sysinfo v1.1.3 // indirect
	github.com/zeebo/blake3 v0.2.3 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/arch v0.8.0 // indirect
	golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f // indirect
	golang.org/x/mod v0.39.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173 // indirect
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10 // indirect
	golang.zx2c4.com/wireguard/windows v0.5.3 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260928230214-8a89bd6388cc // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260928230214-8a89bd6388cc // indirect
	google.golang.org/grpc v1.83.2 // indirect
	gopkg.in/evanphx/json-patch.v4 v4.12.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gvisor.dev/gvisor v0.0.0-20260219192049-0f2374377e89 // indirect
	howett.net/plist v1.0.2-0.20250314012144-ee69052608d9 // indirect
	k8s.io/apimachinery v0.31.1 // indirect
	k8s.io/client-go v0.31.1 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
)

require (
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/go-errors/errors v1.4.2 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-openapi/jsonpointer v0.23.2 // indirect
	github.com/go-openapi/jsonreference v0.21.0 // indirect
	github.com/go-openapi/swag v0.23.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/gregjones/httpcache v0.0.0-20190611155906-901d90724c79 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/imdario/mergo v0.3.13 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jedib0t/go-pretty/v6 v6.3.1
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
	github.com/liggitt/tabwriter v0.0.0-20181228230101-89fcab3d43de // indirect
	github.com/mailru/easyjson v0.9.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/mitchellh/colorstring v0.0.0-20190213212951-d06e56a500db // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/monochromegane/go-gitignore v0.0.0-20200626010858-205db1a8cc00 // indirect
	github.com/peterbourgon/diskv v2.0.1+incompatible // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/spf13/pflag v1.0.10
	github.com/xlab/treeprint v1.2.0 // indirect
	go.starlark.net v0.0.0-20230525235612-a134d8f9ddca // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sys v0.47.0
	golang.org/x/term v0.45.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	google.golang.org/protobuf v1.36.12
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/api v0.31.1 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
	k8s.io/kube-openapi v0.0.0-20240228011516-70dd3763d340 // indirect
	k8s.io/utils v0.0.0-20240711033017-18e509b52bc8 // indirect
	sigs.k8s.io/kustomize/api v0.17.2 // indirect
	sigs.k8s.io/kustomize/kyaml v0.17.1 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
	sigs.k8s.io/yaml v1.4.0 // indirect
)

// Replace directives copied from netbird's go.mod; a consumer module does not inherit them.
replace golang.zx2c4.com/wireguard => github.com/netbirdio/wireguard-go v0.0.0-20260914123147-8bf8fa968f1a

replace github.com/pion/ice/v4 => github.com/netbirdio/ice/v4 v4.0.0-20250908184934-6202be846b51

// Demanded by the first tidy: cunicu.li/go-rosenpass (via client/internal/rosenpass) needs the circl fork's mceliece KEM.
replace github.com/cloudflare/circl => codeberg.org/cunicu/circl v0.0.0-20230801113412-fec58fc7b5f6

// Demanded by tidy only: client/embed's _test.go imports management/server -> idp/dex, which tidy follows.
replace github.com/dexidp/dex => github.com/netbirdio/dex v0.244.1-0.20260716205454-a163de3129e5

replace github.com/dexidp/dex/api/v2 => github.com/netbirdio/dex/api/v2 v2.0.0-20260512110716-8d70ad8647c1
