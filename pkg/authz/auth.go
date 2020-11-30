/*
Copyright 2017 Frederic Branczyk Authors.

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

package authz

import (
	"errors"
	"time"

	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	authorizationclient "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

const (
	Namespace   string = "namespace"
	ApiGroup           = "apiGroup"
	APIVersion         = "apiVersion"
	Resource           = "resource"
	Subresource        = "subresource"
	Name               = "name"
)

// Config holds configuration enabling request authorization
type Config struct {
	Rewrites               *SubjectAccessReviewRewrites `json:"rewrites,omitempty"`
	ResourceAttributes     *ResourceAttributes          `json:"resourceAttributes,omitempty"`
	ResourceAttributesFile string                       `json:"-"`
}

// SubjectAccessReviewRewrites describes how SubjectAccessReview may be
// rewritten on a given request.
type SubjectAccessReviewRewrites struct {
	ByQueryParameter *QueryParameterRewriteConfig `json:"byQueryParameter,omitempty"`
	ByHTTPHeader     *HTTPHeaderRewriteConfig     `json:"byHttpHeader,omitempty"`
}

// QueryParameterRewriteConfig describes which HTTP URL query parameter is to
// be used to rewrite a SubjectAccessReview on a given request.
type QueryParameterRewriteConfig struct {
	Name              string   `json:"name,omitempty"`
	RewriteTargets    []string `json:"rewriteTargets,omitempty"`
	rewriteTargetsSet map[string]struct{}
}

// GetRewriteTargetsSet returns RewriteTargets passed in Config as a Set
func (c *QueryParameterRewriteConfig) GetRewriteTargetsSet() map[string]struct{} {
	return c.rewriteTargetsSet
}

// HTTPHeaderRewriteConfig describes which HTTP header is to
// be used to rewrite a SubjectAccessReview on a given request.
type HTTPHeaderRewriteConfig struct {
	Name              string   `json:"name,omitempty"`
	RewriteTargets    []string `json:"rewriteTargets,omitempty"`
	rewriteTargetsSet map[string]struct{}
}

// GetRewriteTargetsSet returns RewriteTargets passed in Config as a Set
func (c *HTTPHeaderRewriteConfig) GetRewriteTargetsSet() map[string]struct{} {
	return c.rewriteTargetsSet
}

// ResourceAttributes describes attributes available for resource request authorization
type ResourceAttributes struct {
	Namespace   string `json:"namespace,omitempty"`
	APIGroup    string `json:"apiGroup,omitempty"`
	APIVersion  string `json:"apiVersion,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Subresource string `json:"subresource,omitempty"`
	Name        string `json:"name,omitempty"`
}

// InitConfig sets default config values
func InitConfig(cfg *Config) *Config {
	if cfg.Rewrites == nil || cfg.Rewrites.ByQueryParameter == nil && cfg.Rewrites.ByHTTPHeader == nil {
		return cfg
	}
	allResourceAttributesNames := []string{Namespace, ApiGroup, APIVersion, Resource, Subresource, Name}

	if cfg.Rewrites.ByQueryParameter != nil && cfg.Rewrites.ByHTTPHeader == nil && cfg.Rewrites.ByQueryParameter.RewriteTargets == nil {
		cfg.Rewrites.ByQueryParameter.RewriteTargets = allResourceAttributesNames
	} else if cfg.Rewrites.ByHTTPHeader != nil && cfg.Rewrites.ByQueryParameter == nil && cfg.Rewrites.ByHTTPHeader.RewriteTargets == nil {
		cfg.Rewrites.ByHTTPHeader.RewriteTargets = allResourceAttributesNames
	}

	cfg.Rewrites.ByQueryParameter.rewriteTargetsSet = map[string]struct{}{}
	for _, v := range cfg.Rewrites.ByQueryParameter.RewriteTargets {
		cfg.Rewrites.ByQueryParameter.rewriteTargetsSet[v] = struct{}{}
	}
	cfg.Rewrites.ByHTTPHeader.rewriteTargetsSet = map[string]struct{}{}
	for _, v := range cfg.Rewrites.ByHTTPHeader.RewriteTargets {
		cfg.Rewrites.ByHTTPHeader.rewriteTargetsSet[v] = struct{}{}
	}

	return cfg
}

// NewAuthorizer creates an authorizer compatible with the kubelet's needs
func NewAuthorizer(client authorizationclient.SubjectAccessReviewInterface) (authorizer.Authorizer, error) {
	if client == nil {
		return nil, errors.New("no client provided, cannot use webhook authorization")
	}
	authorizerConfig := authorizerfactory.DelegatingAuthorizerConfig{
		SubjectAccessReviewClient: client,
		AllowCacheTTL:             5 * time.Minute,
		DenyCacheTTL:              30 * time.Second,
	}
	return authorizerConfig.New()
}
