/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/elazarl/goproxy"
	egressproxyv1alpha1 "github.com/guilhem/egress-proxy-operator/api/v1alpha1"
)

// RequestReconciler reconciles a Request object
type RequestReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	ReqHandlers   *[]goproxy.ReqHandler
	HttpsHandlers *[]goproxy.HttpsHandler
	// Proxy *goproxy.ProxyHttpServer

	internalReqHandlers   map[string]goproxy.ReqHandler
	internalHttpsHandlers map[string]goproxy.HttpsHandler
	endpointsMap          map[string]map[string]map[string]types.NamespacedName
}

const Finalizer = "egress-proxy.barpilot.io/finalizer"

//+kubebuilder:rbac:groups=egress-proxy.barpilot.io,resources=requests,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=egress-proxy.barpilot.io,resources=requests/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=egress-proxy.barpilot.io,resources=requests/finalizers,verbs=update

//+kubebuilder:rbac:groups=core,resources=endpoints,verbs=get;list;watch
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete

func (r *RequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	proxyReq := new(egressproxyv1alpha1.Request)
	if err := r.Get(ctx, req.NamespacedName, proxyReq); err != nil {
		log.Error(err, "unable to fetch Request")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// examine DeletionTimestamp to determine if object is under deletion
	if proxyReq.ObjectMeta.DeletionTimestamp.IsZero() {
		// The object is not being deleted, so if it does not have our finalizer,
		// then lets add the finalizer and update the object. This is equivalent
		// registering our finalizer.
		if !controllerutil.ContainsFinalizer(proxyReq, Finalizer) {
			controllerutil.AddFinalizer(proxyReq, Finalizer)
			if err := r.Update(ctx, proxyReq); err != nil {
				return ctrl.Result{}, fmt.Errorf("can't add finalizer: %w", err)
			}
		}
	} else {
		// The object is being deleted
		if controllerutil.ContainsFinalizer(proxyReq, Finalizer) {
			// our finalizer is present, so lets handle any removing part
			r.Remove(ctx, proxyReq)

			// remove our finalizer from the list and update it.
			controllerutil.RemoveFinalizer(proxyReq, Finalizer)
			if err := r.Update(ctx, proxyReq); err != nil {
				return ctrl.Result{}, fmt.Errorf("can't remove finalizer: %w", err)
			}
		}

		// Stop reconciliation as the item is being deleted
		return ctrl.Result{}, nil
	}

	if proxyReq.Spec.CASecret != "" {
		caSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: proxyReq.Spec.CASecret, Namespace: req.Namespace}}

		_, err := controllerutil.CreateOrUpdate(ctx, r.Client, caSecret, func() error {
			if err := controllerutil.SetControllerReference(proxyReq, caSecret, r.Scheme); err != nil {
				return err
			}
			caSecret.Type = corev1.SecretTypeOpaque

			if caSecret.Data == nil {
				caSecret.Data = make(map[string][]byte)
			}
			caSecret.Data[corev1.ServiceAccountRootCAKey] = goproxy.CA_CERT
			return nil
		})
		if err != nil {
			return reconcile.Result{}, err
		}
	}

	if err := r.Add(ctx, proxyReq); err != nil {
		return ctrl.Result{}, fmt.Errorf("can't add proxy req: %w", err)
	}

	log.Info("finish")

	// log.V(4).Info("finish parsing", "handlers", r.ReqHandlers)

	return ctrl.Result{}, nil
}

func (r *RequestReconciler) Add(ctx context.Context, req *egressproxyv1alpha1.Request) error {
	log := log.FromContext(ctx)

	conds := make(map[string][]goproxy.ReqCondition)
	for _, dst := range req.Spec.Condition.DestinationHosts {
		conds["dst"] = append(conds["dst"], goproxy.DstHostIs(dst))
		log.Info("Add condition", "dst", dst)
	}

	for _, rule := range req.Spec.Condition.Urls.Matches {
		match, err := regexp.Compile(rule)
		if err != nil {
			return err
		}
		conds["matches"] = append(conds["matches"], goproxy.ReqHostMatches(match))
		log.Info("Add condition", "matches", rule)
	}

	for _, prefix := range req.Spec.Condition.Urls.Prefixes {
		conds["prefixes"] = append(conds["prefixes"], goproxy.UrlHasPrefix(prefix))
		log.Info("Add condition", "prefix", prefix)
	}

	for _, are := range req.Spec.Condition.Urls.Are {
		conds["are"] = append(conds["are"], goproxy.UrlIs(are))
		log.Info("Add condition", "are", are)
	}

	if req.Spec.Condition.SourceEndpoints != "" {
		ep := new(corev1.Endpoints)
		if err := r.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: req.Spec.Condition.SourceEndpoints}, ep); err != nil {
			return fmt.Errorf("can't get sourceEndpoint: %w", err)
		}

		var ips []string

		for _, s := range ep.Subsets {
			for _, addr := range s.Addresses {
				ips = append(ips, addr.IP)
			}
		}

		conds["ip"] = append(conds["ip"], goproxy.SrcIpIs(ips...))
		log.Info("Add condition", "ips", ips)

		// init endpointsMap if needed
		if _, ok := r.endpointsMap[req.Namespace]; !ok {
			r.endpointsMap[req.Namespace] = make(map[string]map[string]types.NamespacedName)
		}

		if _, ok := r.endpointsMap[req.Namespace][req.Spec.Condition.SourceEndpoints]; !ok {
			r.endpointsMap[req.Namespace][req.Spec.Condition.SourceEndpoints] = make(map[string]types.NamespacedName)
		}

		r.endpointsMap[req.Namespace][req.Spec.Condition.SourceEndpoints][string(req.UID)] = types.NamespacedName{Name: req.Name, Namespace: req.Namespace}
	}

	httpshandler := goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		// log = log.WithValues("host", host)

		log.Info("handle connect", "host", host)

		hostname, _, err := net.SplitHostPort(host)
		if err != nil {
			// error is not an option, literally
			log.Error(err, "can't parse host")
			return goproxy.OkConnect, host
		}

		trigger := false
		// if len(conds["are"]) == 0 && len(conds["prefixes"]) == 0 && len(conds["matches"]) == 0 {
		for _, dst := range req.Spec.Condition.DestinationHosts {
			log.Info("destinationhost", "dst", dst, "hostname", hostname)
			if hostname == dst {
				trigger = true
				break
			}
		}
		// } else {
		// 	log.Info("conditions are too precise for httpshandler")
		// }

		if !trigger {
			log.Info("no trigger")
			return goproxy.OkConnect, host
		}

		if req.Spec.Action.Block {
			log.Info("Reject")
			return goproxy.RejectConnect, host
		}

		log.Info("MitmConnect")
		return goproxy.MitmConnect, host

	})

	reqhandler := goproxy.FuncReqHandler(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		log.Info("handle request", "url", r.URL.String())
		for _, group := range conds {
			trigger := false
			for _, cond := range group {
				if cond.HandleReq(r, ctx) {
					trigger = true
					break
				}
			}
			if !trigger {
				log.Info("no condition match")
				return r, nil
			}
		}

		if req.Spec.Action.Block {
			log.Info("Block request")
			return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden, fmt.Sprintf("blocked by rule %s\n", req.Name))
		}

		if route := req.Spec.Action.Reroute; route != "" {
			log.Info("reroute request", "target", route)
			target, err := url.Parse(route)
			if err != nil {
				log.Info("can't parse route", "route", route)
				return r, nil
			}
			// reverse := httputil.NewSingleHostReverseProxy(u)
			targetQuery := target.RawQuery
			reverse := httputil.ReverseProxy{
				Director: func(req *http.Request) {
					req.URL.Scheme = target.Scheme
					req.URL.Host = target.Host
					req.Host = target.Host //replace host header
					req.URL.Path, req.URL.RawPath = joinURLPath(target, req.URL)
					if targetQuery == "" || req.URL.RawQuery == "" {
						req.URL.RawQuery = targetQuery + req.URL.RawQuery
					} else {
						req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
					}
					if _, ok := req.Header["User-Agent"]; !ok {
						// explicitly disable User-Agent so it's not set to default value
						req.Header.Set("User-Agent", "")
					}
				},
			}

			rw := httptest.NewRecorder()

			log.Info("request proxies", "r", r.URL)

			reverse.ServeHTTP(rw, r)

			return r, rw.Result()
		}

		log.Info("Nothing to do with request")
		return r, nil
	})

	r.internalHttpsHandlers[string(req.UID)] = httpshandler
	// r.ReqHandlers = r.ReqHandlers[:0]
	r.internalReqHandlers[string(req.UID)] = reqhandler

	r.refresh(ctx)

	return nil
}

func (r *RequestReconciler) Remove(ctx context.Context, req *egressproxyv1alpha1.Request) {
	k := string(req.UID)

	// cleanup internalReqHandlers
	if _, ok := r.internalReqHandlers[k]; ok {
		delete(r.internalReqHandlers, string(req.UID))
		r.refresh(ctx)
	}

	// cleanup internalReqHandlers
	if _, ok := r.internalHttpsHandlers[k]; ok {
		delete(r.internalHttpsHandlers, string(req.UID))
		r.refresh(ctx)
	}

	// cleanup endpointsMap
	for _, m := range r.endpointsMap {
		for _, n := range m {
			for i := range n {
				if i == k {
					delete(n, i)
				}
			}
		}
	}
}

func (r *RequestReconciler) refresh(ctx context.Context) {
	log := log.FromContext(ctx)

	nHttpsHandlers := make([]goproxy.HttpsHandler, 0, len(r.internalHttpsHandlers))

	for _, i := range r.internalHttpsHandlers {
		nHttpsHandlers = append(nHttpsHandlers, i)
	}

	nReqHandlers := make([]goproxy.ReqHandler, 0, len(r.internalReqHandlers))

	for _, i := range r.internalReqHandlers {
		nReqHandlers = append(nReqHandlers, i)
	}

	log.V(2).Info("refresh: update pointer")

	*r.HttpsHandlers = nHttpsHandlers
	*r.ReqHandlers = nReqHandlers
}

// SetupWithManager sets up the controller with the Manager.
func (r *RequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// TODO NewReciler func
	r.endpointsMap = make(map[string]map[string]map[string]types.NamespacedName)
	r.internalReqHandlers = make(map[string]goproxy.ReqHandler)
	r.internalHttpsHandlers = make(map[string]goproxy.HttpsHandler)

	f := func(o client.Object) []reconcile.Request {
		req := []reconcile.Request{}

		if n, ok := r.endpointsMap[o.GetNamespace()]; ok {
			if s, ok := n[o.GetName()]; ok {
				for _, t := range s {
					req = append(req, reconcile.Request{NamespacedName: t})
				}
			}
		}

		return req
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&egressproxyv1alpha1.Request{}).
		Watches(&source.Kind{Type: &corev1.Endpoints{}}, handler.EnqueueRequestsFromMapFunc(f), builder.OnlyMetadata).
		Owns(&corev1.Secret{}).
		Complete(r)
}

func joinURLPath(a, b *url.URL) (path, rawpath string) {
	if a.RawPath == "" && b.RawPath == "" {
		return singleJoiningSlash(a.Path, b.Path), ""
	}
	// Same as singleJoiningSlash, but uses EscapedPath to determine
	// whether a slash should be added
	apath := a.EscapedPath()
	bpath := b.EscapedPath()

	aslash := strings.HasSuffix(apath, "/")
	bslash := strings.HasPrefix(bpath, "/")

	switch {
	case aslash && bslash:
		return a.Path + b.Path[1:], apath + bpath[1:]
	case !aslash && !bslash:
		return a.Path + "/" + b.Path, apath + "/" + bpath
	}
	return a.Path + b.Path, apath + bpath
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
