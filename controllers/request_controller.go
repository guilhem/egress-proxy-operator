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
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"regexp"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/elazarl/goproxy"
	egressproxyv1alpha1 "github.com/guilhem/egress-proxy-operator/api/v1alpha1"
)

// RequestReconciler reconciles a Request object
type RequestReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// ReqHandlers []goproxy.ReqHandler
	Proxy *goproxy.ProxyHttpServer
}

//+kubebuilder:rbac:groups=egress-proxy.barpilot.io,resources=requests,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=egress-proxy.barpilot.io,resources=requests/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=egress-proxy.barpilot.io,resources=requests/finalizers,verbs=update

func (r *RequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	proxyReq := new(egressproxyv1alpha1.Request)
	if err := r.Get(ctx, req.NamespacedName, proxyReq); err != nil {
		log.Error(err, "unable to fetch Request")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	proxyList := new(egressproxyv1alpha1.RequestList)
	if err := r.List(ctx, proxyList); err != nil {
		log.Error(err, "unable to get proxy list")
	}

	var tmp []goproxy.ReqHandler
	for _, req := range proxyList.Items {

		conds := make(map[string][]goproxy.ReqCondition)
		for _, dst := range req.Spec.Condition.DestinationHosts {
			conds["dst"] = append(conds["dst"], goproxy.DstHostIs(dst))
		}

		for _, rule := range req.Spec.Condition.Urls.Matches {
			match, err := regexp.Compile(rule)
			if err != nil {
				return reconcile.Result{}, err
			}
			conds["matches"] = append(conds["matches"], goproxy.ReqHostMatches(match))
		}

		for _, prefix := range req.Spec.Condition.Urls.Prefixes {
			conds["prefixes"] = append(conds["prefixes"], goproxy.UrlHasPrefix(prefix))
		}

		for _, are := range req.Spec.Condition.Urls.Are {
			conds["are"] = append(conds["are"], goproxy.UrlIs(are))
		}

		tmp = append(tmp, goproxy.FuncReqHandler(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			log.Info("funcReqHandler")

			for _, group := range conds {
				trigger := false
				for _, cond := range group {
					if cond.HandleReq(r, ctx) {
						trigger = true
						break
					}
				}
				if !trigger {
					return r, nil
				}
			}
			var resp *http.Response

			if req.Spec.Action.Block {
				resp = goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden, fmt.Sprintf("blocked by rule %s", req.Name))
			}

			if route := req.Spec.Action.Reroute; route != "" {
				u, err := url.Parse(route)
				if err != nil {
					return r, nil
				}
				reverse := httputil.NewSingleHostReverseProxy(u)

				rw := httptest.NewRecorder()

				reverse.ServeHTTP(rw, r)
				resp = rw.Result()
			}
			return r, resp
		}))
	}

	// r.ReqHandlers = r.ReqHandlers[:0]
	r.Proxy.ReqHandlers = tmp

	log.Info("finish", "handlers", len(tmp))

	// log.V(4).Info("finish parsing", "handlers", r.ReqHandlers)

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&egressproxyv1alpha1.Request{}).
		Complete(r)
}
