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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// RequestSpec defines the desired state of Request
type RequestSpec struct {
	Condition Condition `json:"condition,omitempty"`
	Action    Action    `json:"action,omitempty"`
}

type Action struct {
	Reroute string `json:"reroute,omitempty"`
	Block   bool   `json:"block,omitempty"`
}

type Condition struct {
	DestinationHosts []string `json:"destinations,omitempty"`
	Urls             URL      `json:"urls,omitempty"`

	SourceEndpoints string `json:"sourceEndpoints,omitempty"`
}

type URL struct {
	Prefixes []string `json:"prefixes,omitempty"`
	Matches  []string `json:"matches,omitempty"`
	Are      []string `json:"are,omitempty"`
}

// RequestStatus defines the observed state of Request
type RequestStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Request is the Schema for the requests API
type Request struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RequestSpec   `json:"spec,omitempty"`
	Status RequestStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// RequestList contains a list of Request
type RequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Request `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Request{}, &RequestList{})
}
