// scenepkg.go — Scene package read helpers (RP side).
package tden

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// FieldRequest mirrors a single requested attribute.
type FieldRequest struct {
	Tag           string `json:"tag"`
	Required      bool   `json:"required"`
	Justification string `json:"justification"`
}

// ScenePackage mirrors the gateway response.
type ScenePackage struct {
	PackageID           string         `json:"package_id"`
	PackageName         string         `json:"package_name"`
	Version             string         `json:"version"`
	DeveloperDID        string         `json:"developer_did"`
	InstitutionType     string         `json:"institution_type"`
	InstitutionVerified bool           `json:"institution_verified"`
	Fields              []FieldRequest `json:"fields"`
	Purpose             string         `json:"purpose"`
	LawfulBasis         string         `json:"lawful_basis"`
	AuthTypes           []string       `json:"auth_types"`
	MaxValiditySeconds  int64          `json:"max_validity_seconds"`
	MaxQueriesPerDay    int            `json:"max_queries_per_day"`
	RedirectURIs        []string       `json:"redirect_uris"`
	SensitivityLevel    string         `json:"sensitivity_level"`
	ReviewStatus        string         `json:"review_status"`
	ClientID            string         `json:"client_id,omitempty"`
	ApprovedAt          int64          `json:"approved_at,omitempty"`
	CreatedAt           int64          `json:"created_at"`
	UpdatedAt           int64          `json:"updated_at"`
}

// ScenePackages is a thin read-only client for /api/scenepackages.
type ScenePackages struct {
	GatewayURL string
	HTTPClient *http.Client
}

// NewScenePackages constructs a ScenePackages reader with sane defaults.
func NewScenePackages(gatewayURL string) *ScenePackages {
	if gatewayURL == "" {
		gatewayURL = "https://gateway.tden.network"
	}
	return &ScenePackages{
		GatewayURL: strings.TrimRight(gatewayURL, "/"),
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// ListApproved returns every globally-approved scene package.
func (s *ScenePackages) ListApproved(ctx context.Context) ([]*ScenePackage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.GatewayURL+"/api/scenepackages", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tden: scenepackages list HTTP %d", resp.StatusCode)
	}
	var body struct {
		Packages []*ScenePackage `json:"packages"`
		Count    int             `json:"count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return body.Packages, nil
}

// Get fetches a single approved package; returns (nil, nil) on 404.
func (s *ScenePackages) Get(ctx context.Context, packageID string) (*ScenePackage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		s.GatewayURL+"/api/scenepackages/"+packageID, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tden: scenepackages get HTTP %d", resp.StatusCode)
	}
	var p ScenePackage
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, err
	}
	return &p, nil
}
