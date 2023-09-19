package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/lestrrat-go/jwx/jwk"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

type jwtConfig struct {
	BoundIssuer          string   `json:"bound_issuer"`
	DefaultRole          string   `json:"default_role"`
	JwksCaPem            string   `json:"jwks_ca_pem"`
	JwksURL              string   `json:"jwks_url"`
	JwtSupportedAlgs     []any    `json:"jwt_supported_algs"`
	JwtValidationPubkeys []string `json:"jwt_validation_pubkeys"`
	NamespaceInState     bool     `json:"namespace_in_state"`
	OidcClientID         string   `json:"oidc_client_id"`
	OidcDiscoveryCaPem   string   `json:"oidc_discovery_ca_pem"`
	OidcDiscoveryURL     string   `json:"oidc_discovery_url"`
	OidcResponseMode     string   `json:"oidc_response_mode"`
	OidcResponseTypes    []any    `json:"oidc_response_types"`
	ProviderConfig       struct {
	} `json:"provider_config"`
}

type vaultAuthData struct {
	Addr          string `json:"vaultAddr,omitempty"`
	Namespace     string `json:"vaultNamespace,omitempty"`
	AuthMethod    string `json:"vaultAuthMethod,omitempty"`
	AuthRole      string `json:"vaultAuthRole,omitempty"`
	AuthMountPath string `json:"vaultAuthMountPath,omitempty"`
	AuthJwt       string `json:"vaultAuthJwt,omitempty"`
}

func getJwksData(config *rest.Config) []byte {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	discoveryClient := clientset.RESTClient().Get().AbsPath("/.well-known/openid-configuration")
	discoveryData, err := discoveryClient.DoRaw(context.Background())
	if err != nil {
		panic(err.Error())
	}

	var discoveryDataInterface map[string]interface{}
	err = json.Unmarshal(discoveryData, &discoveryDataInterface)
	if err != nil {
		panic(err.Error())
	}

	jwksUri := discoveryDataInterface["jwks_uri"].(string)
	endpoint, err := clientset.CoreV1().Endpoints("default").Get(context.Background(), "kubernetes", v1.GetOptions{})
	if err != nil {
		panic(err.Error())
	}

	var endpointAddress string
	endpointScheme := endpoint.Subsets[0].Ports[0].Name
	endpointAddresses := endpoint.Subsets[0].Addresses[0]
	endpointPort := endpoint.Subsets[0].Ports[0].Port
	if len(endpointAddresses.Hostname) > 0 {
		endpointAddress = endpointAddresses.Hostname
	} else {
		endpointAddress = endpointAddresses.IP
	}

	endpointUri := fmt.Sprintf("%s://%s:%d", endpointScheme, endpointAddress, endpointPort)
	jwksApiPath := strings.Split(jwksUri, endpointUri)[1]
	jwksPayload := clientset.RESTClient().Get().AbsPath(jwksApiPath)

	jwksData, err := jwksPayload.DoRaw(context.Background())
	if err != nil {
		panic(err.Error())
	}

	return jwksData
}

func jwks2pem(jwksData []byte) string {
	set, err := jwk.Parse(jwksData)
	if err != nil {
		log.Fatal("JWKS parsing failed")
	} else {
		log.Println("Successfully parsed JWKS:", string(jwksData))
	}

	pem, err := jwk.Pem(set)
	if err != nil {
		log.Fatal("PEM conversion failed")
	} else {
		log.Println("Sucessfully converted JWKS to PEM format:", strings.ReplaceAll(strings.TrimSpace(string(pem)), "\n", `\n`))
	}
	pemString := strings.TrimSpace(string(pem))

	return pemString
}

func (v *vaultAuthData) authenticate(ctx context.Context) *vault.Client {

	client, err := vault.New(
		vault.WithAddress(v.Addr),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		log.Fatal(err)
	}
	if v.Namespace != "" {
		client.SetNamespace(v.Namespace)
	}

	switch authMethod := v.AuthMethod; authMethod {
	case "azure":
		var (
			jwt string
			rg  string
			sub string
			rId string
		)
		httpClient := &http.Client{
			Timeout: 5 * time.Second,
		}

		if v.AuthJwt == "" {
			req, _ := http.NewRequest("GET", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F", nil)
			req.Header.Add("Metadata", "true")
			resp, err := httpClient.Do(req)
			if err != nil {
				panic(err.Error())
			}

			var msiPayload map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&msiPayload)
			if err != nil {
				panic(err.Error())
			}
			if _, ok := msiPayload["access_token"]; ok {
				jwt = msiPayload["access_token"].(string)
			}
		} else {
			jwt = v.AuthJwt
		}

		req, _ := http.NewRequest("GET", "http://169.254.169.254/metadata/instance/compute?api-version=2021-10-01", nil)
		req.Header.Add("Metadata", "true")
		resp, err := httpClient.Do(req)
		if err != nil {
			panic(err.Error())
		}

		var msiPayload map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&msiPayload)
		if err != nil {
			panic(err.Error())
		}

		if _, ok := msiPayload["resourceGroupName"]; ok {
			rg = msiPayload["resourceGroupName"].(string)
		}
		if _, ok := msiPayload["subscriptionId"]; ok {
			sub = msiPayload["subscriptionId"].(string)
		}
		if _, ok := msiPayload["resourceId"]; ok {
			rId = msiPayload["resourceId"].(string)
		}

		vaultLogin, err := client.Auth.AzureLogin(ctx, schema.AzureLoginRequest{
			Jwt:               jwt,
			Role:              v.AuthRole,
			ResourceGroupName: rg,
			SubscriptionId:    sub,
			ResourceId:        rId,
		},
			vault.WithMountPath(v.AuthMountPath),
		)
		if err != nil {
			panic(err.Error())
		}
		client.SetToken(vaultLogin.Auth.ClientToken)

	case "jwt":
		jwt := v.AuthJwt
		vaultLogin, err := client.Auth.JwtLogin(ctx, schema.JwtLoginRequest{
			Jwt:  jwt,
			Role: v.AuthRole,
		},
			vault.WithMountPath(v.AuthMountPath),
		)
		if err != nil {
			panic(err.Error())
		}
		client.SetToken(vaultLogin.Auth.ClientToken)
	}

	log.Println("Successfully authenticated with Vault server:", client.Configuration().Address)

	return client
}

func getJwtConfig(ctx context.Context, vaultClient *vault.Client, targetJwtAuthMountPath string) jwtConfig {
	currentJwtConfig, err := vaultClient.Read(ctx, "auth/"+targetJwtAuthMountPath+"/config")
	if err != nil {
		panic(err.Error())
	}

	jwtConfigJson, err := json.Marshal(currentJwtConfig.Data)
	if err != nil {
		panic(err.Error())
	}

	var jwtConfigStruct jwtConfig
	err = json.Unmarshal(jwtConfigJson, &jwtConfigStruct)
	if err != nil {
		panic(err.Error())
	}

	return jwtConfigStruct
}

func updateJwtConfig(ctx context.Context, vaultClient *vault.Client, jwtConfig jwtConfig, targetJwtAuthMountPath string) {
	var payload map[string]interface{}
	payloadBytes, err := json.Marshal(jwtConfig)
	if err != nil {
		panic(err.Error())
	}

	json.Unmarshal(payloadBytes, &payload)
	_, err = vaultClient.Write(ctx, "auth/"+targetJwtAuthMountPath+"/config", payload)
	if err != nil {
		panic(err.Error())
	} else {
		log.Println("Successfully modified public keys for target auth method")
	}
}

func removeSlice(s []string, r string) ([]string, bool) {
	for i, v := range s {
		if v == r {
			log.Println("Found matching key for removal")
			return append(s[:i], s[i+1:]...), true
		}
	}
	log.Println("No matching keys found for removal")
	return s, false
}

func main() {
	var (
		vaultAuthData          vaultAuthData
		targetJwtAuthMountPath string
		installKey             bool
		revokeKey              bool
	)
	ctx := context.Background()

	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}

	flag.StringVar(&vaultAuthData.Addr, "vaultAddr", "http://127.0.0.1:8200", "Vault Address")
	flag.StringVar(&vaultAuthData.Namespace, "vaultNamespace", "", "Vault Namespace")
	flag.StringVar(&vaultAuthData.AuthMountPath, "vaultAuthMountPath", "azure", "The Vault Auth Mount Path used to authenticate this application")
	flag.StringVar(&vaultAuthData.AuthMethod, "vaultAuthMethod", "azure", "Vault Auth Method (valid options are 'jwt' or 'azure')")
	flag.StringVar(&vaultAuthData.AuthRole, "vaultAuthRole", "", "Vault Auth Method role name")
	flag.StringVar(&vaultAuthData.AuthJwt, "vaultAuthJwt", "", "JWT token to use while authenticating this application to Vault - valid for both JWT and Azure auth methods")
	flag.StringVar(&targetJwtAuthMountPath, "targetJwtAuthMountPath", "", "The Auth Method mount path where the the new public key should be installed")
	flag.BoolVar(&revokeKey, "revoke", false, "If true, the key will be revoked from the target Vault Auth Method")
	flag.Parse()

	log.Printf("Using %s Auth Method at mountpoint auth/%s\n", vaultAuthData.AuthMethod, vaultAuthData.AuthMethod)

	if vaultAuthData.AuthMethod == "" {
		log.Fatal("A valid vaultAuthRole must be specified")
	}

	if targetJwtAuthMountPath == "" {
		log.Fatal("A valid targetJwtAuthMountPath must be specified")
	}

	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		log.Fatal("No valid kubeconfig found")
	} else {
		log.Println("Using kubeconfig:", *kubeconfig)
	}

	jwksData := getJwksData(config)
	pemString := jwks2pem(jwksData)

	vaultClient := vaultAuthData.authenticate(ctx)
	jwtConfig := getJwtConfig(ctx, vaultClient, targetJwtAuthMountPath)

	if revokeKey {
		x, modified := removeSlice(jwtConfig.JwtValidationPubkeys, pemString)
		if !modified {
			log.Println("No modifications required")
			os.Exit(0)
		}
		jwtConfig.JwtValidationPubkeys = x
		updateJwtConfig(ctx, vaultClient, jwtConfig, targetJwtAuthMountPath)
	} else {
		installKey = true
		for _, v := range jwtConfig.JwtValidationPubkeys {
			if v == pemString {
				log.Println("Public key already present in configuration")
				installKey = false
				break
			}
		}
		if installKey {
			x := append(jwtConfig.JwtValidationPubkeys, pemString)
			jwtConfig.JwtValidationPubkeys = x
			updateJwtConfig(ctx, vaultClient, jwtConfig, targetJwtAuthMountPath)
		}
	}
}
