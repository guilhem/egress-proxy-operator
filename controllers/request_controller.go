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
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/elazarl/goproxy"
	egressproxyv1alpha1 "github.com/guilhem/egress-proxy-operator/api/v1alpha1"
)

// RequestReconciler reconciles a Request object
type RequestReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	ReqHandlers []goproxy.ReqHandler
	// Proxy *goproxy.ProxyHttpServer

	internalReqHandlers map[string]goproxy.ReqHandler
}

const Finalizer = "egress-proxy.barpilot.io/finalizer"

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
			// our finalizer is present, so lets handle any external dependency
			r.Remove(proxyReq)

			// remove our finalizer from the list and update it.
			controllerutil.RemoveFinalizer(proxyReq, Finalizer)
			if err := r.Update(ctx, proxyReq); err != nil {
				return ctrl.Result{}, fmt.Errorf("can't remove finalizer: %w", err)
			}
		}

		// Stop reconciliation as the item is being deleted
		return ctrl.Result{}, nil
	}

	if err := r.Add(proxyReq); err != nil {
		return ctrl.Result{}, fmt.Errorf("can't add proxy req: %w", err)
	}

	log.Info("finish")

	// log.V(4).Info("finish parsing", "handlers", r.ReqHandlers)

	return ctrl.Result{}, nil
}

func (r *RequestReconciler) Add(req *egressproxyv1alpha1.Request) error {
	conds := make(map[string][]goproxy.ReqCondition)
	for _, dst := range req.Spec.Condition.DestinationHosts {
		conds["dst"] = append(conds["dst"], goproxy.DstHostIs(dst))
	}

	for _, rule := range req.Spec.Condition.Urls.Matches {
		match, err := regexp.Compile(rule)
		if err != nil {
			return err
		}
		conds["matches"] = append(conds["matches"], goproxy.ReqHostMatches(match))
	}

	for _, prefix := range req.Spec.Condition.Urls.Prefixes {
		conds["prefixes"] = append(conds["prefixes"], goproxy.UrlHasPrefix(prefix))
	}

	for _, are := range req.Spec.Condition.Urls.Are {
		conds["are"] = append(conds["are"], goproxy.UrlIs(are))
	}

	reqhandler := goproxy.FuncReqHandler(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
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
	})

	// r.ReqHandlers = r.ReqHandlers[:0]
	r.internalReqHandlers[string(req.UID)] = reqhandler

	r.refresh()

	return nil
}

func (r *RequestReconciler) Remove(req *egressproxyv1alpha1.Request) {
	k := string(req.UID)
	if _, ok := r.internalReqHandlers[k]; ok {
		delete(r.internalReqHandlers, string(req.UID))
		r.refresh()
	}
}

func (r *RequestReconciler) refresh() {
	var nReqHandlers []goproxy.ReqHandler

	for _, i := range r.internalReqHandlers {
		nReqHandlers = append(nReqHandlers, i)
	}

	r.ReqHandlers = nReqHandlers
}

// SetupWithManager sets up the controller with the Manager.
func (r *RequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&egressproxyv1alpha1.Request{}).
		Complete(r)
}
