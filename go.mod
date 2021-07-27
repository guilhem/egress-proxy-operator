module github.com/guilhem/egress-proxy-operator

go 1.16

require (
	github.com/elazarl/goproxy v0.0.0-20210110162100-a92cc753f88e
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.2
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	k8s.io/apimachinery v0.20.2
	k8s.io/client-go v0.20.2
	sigs.k8s.io/controller-runtime v0.8.3
)

replace github.com/elazarl/goproxy => github.com/guilhem/goproxy v0.0.0-20210715213258-c25598659d73
