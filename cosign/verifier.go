/*
Copyright The Ratify Authors.
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

package cosign

import (
	"context"
	"encoding/json"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/ratify-project/ratify-go"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/sigstore-go/pkg/root"
)

const (
	cosignVerifierType = "cosign"
	cosignArtifactType = "application/vnd.dev.cosign.artifact.sig.v1+json"
)

type Verifier struct {
	name             string
	trustedMaterials map[string]root.TrustedMaterial
	// trustedRoot *prototrustroot.TrustedRoot
}

type VerifierOptions struct {
	// Name is the instance name of the verifier to be created. Required.
	Name string

	// TrustedMaterials is the trusted material collection to use for
	// verification. It should mapping to the sigature to the trust material.
	// Optimized for the cosign verifier referring the multiplexer.
	TrustedMaterials map[string]root.TrustedMaterial
}

// TODO: handle the root trust import
// TODO: handle the trust material to checkOpts parsing
func NewVerifier(opts *VerifierOptions) ratify.Verifier {
	return &Verifier{
		name:             opts.Name,
		trustedMaterials: opts.TrustedMaterials,
		// trustedRoot: root.NewTrustedRoot()
	}
}

func (v *Verifier) Name() string {
	return v.name
}

func (v *Verifier) Type() string {
	return cosignVerifierType
}

func (v *Verifier) Verifiable(artifact ocispec.Descriptor) bool {
	return artifact.ArtifactType == cosignArtifactType && artifact.MediaType == ocispec.MediaTypeImageManifest
}

// Verify the artifact using the cosign verifier
// There are only 2 kinds of verification right now:
//  1. You gave us the public key explicitly to verify against so co.SigVerifier is non-nil or,
//  2. We’re going to find an x509 certificate on the signature and verify against
//     Fulcio root trust (or user supplied root trust)
func (v *Verifier) Verify(ctx context.Context, opts *ratify.VerifyOptions) (*ratify.VerificationResult, error) {
	sig, err := v.CosignSignature(ctx, opts.Store, opts.Repository, opts.ArtifactDescriptor)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cosign signature: %w", err)
	}
	// create the hash of the subject image descriptor (used as the hashed payload)
	subjectDescHash := v1.Hash{
		Algorithm: opts.SubjectDescriptor.Digest.Algorithm().String(),
		Hex:       opts.SubjectDescriptor.Digest.Hex(),
	}

	// TODO: parse the CheckOpts from the VerifyOptions
	cosignOpts := cosign.CheckOpts{}

	// REF: https://github.com/sigstore/cosign/blob/main/pkg/cosign/verify.go#L715
	cosign.VerifyImageSignature(ctx, sig, subjectDescHash, &cosignOpts)

	// Create a VerificationResult based on the verification result
	verificationResult := &ratify.VerificationResult{}

	return verificationResult, nil
}

type Payloader interface {
	// no-op for attestations
	Base64Signature() (string, error)
	Payload() ([]byte, error)
}

func (v *Verifier) CosignSignature(ctx context.Context, store ratify.Store, repository string, artifact ocispec.Descriptor) (oci.Signature, error) {
	// get the signature from the store
	blobBytes, err := store.FetchBlob(ctx, repository, artifact)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch signature blob: %w", err)
	}

	staticOpts, err := staticLayerOpts(artifact)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cosign signature annotation: %w", err)
	}

	sig, err := static.NewSignature(blobBytes, artifact.Annotations[static.SignatureAnnotationKey], staticOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to form a cosign signature: %w", err)
	}
	return sig, nil
}

// TODO: optimize with latest implementation
// REF: https://github.com/sigstore/cosign/blob/main/pkg/oci/static/options.go#L27
func staticLayerOpts(desc ocispec.Descriptor) ([]static.Option, error) {
	options := []static.Option{}
	options = append(options, static.WithAnnotations(desc.Annotations))
	cert := desc.Annotations[static.CertificateAnnotationKey]
	chain := desc.Annotations[static.ChainAnnotationKey]
	if cert != "" && chain != "" {
		options = append(options, static.WithCertChain([]byte(cert), []byte(chain)))
	}
	var rekorBundle bundle.RekorBundle
	if val, ok := desc.Annotations[static.BundleAnnotationKey]; ok {
		if err := json.Unmarshal([]byte(val), &rekorBundle); err != nil {
			return nil, fmt.Errorf("failed to unmarshal bundle from blob payload: %w", err)
		}
		options = append(options, static.WithBundle(&rekorBundle))
	}

	return options, nil
}
