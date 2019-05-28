package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/namsral/flag"
)

func main() {
	c := parse()

	err := VaultSetup(c)
	if err != nil {
		log.Fatal(err)
	}
}

type config struct {
	vaultScheme string
	vaultHost   string
	vaultToken  string

	rootMount       string
	rootMaxLeaseTTL string
	rootCommonName  string
	rootTTL         string

	intermediateMount       string
	intermediateMaxLeaseTTL string
	intermediateCommonName  string
	intermediateTTL         string

	intermediateSignFormat string
	intermediateSignTTL    string

	intermediateRole                string
	intermediateRoleAllowedDomains  string
	intermediateRoleAllowSubdomains bool
	intermediateRoleMaxTTL          string
}

func parse() *config {
	c := &config{}

	flag.StringVar(&c.vaultScheme, "vault-scheme", "http", "Scheme of vault host")
	flag.StringVar(&c.vaultHost, "vault-host", "localhost:8200", "Host of vault")
	flag.StringVar(&c.vaultToken, "vault-token", "", "Root token of vault")

	flag.StringVar(&c.rootMount, "root-mount", "pki", "Root CA's mount")
	flag.StringVar(&c.rootMaxLeaseTTL, "root-max-lease-ttl", "87600h", "Root CA's max lease TTL")
	flag.StringVar(&c.rootCommonName, "root-common-name", "", "Root CA's common name")
	flag.StringVar(&c.rootTTL, "root-ttl", "87600h", "Root CA's TTL")

	flag.StringVar(&c.intermediateMount, "intermediate-mount", "pki_int", "Intermediate CA's mount")
	flag.StringVar(&c.intermediateMaxLeaseTTL, "intermediate-max-lease-ttl", "43800h", "Intermediate CA's max lease TTL")
	flag.StringVar(&c.intermediateCommonName, "intermediate-common-name", "", "Intermediate CA's common name")
	flag.StringVar(&c.intermediateTTL, "intermediate-ttl", "43800h", "Intermediate CA's TTL")

	flag.StringVar(&c.intermediateSignFormat, "intermediate-sign-format", "pem_bundle", "Sign format of Root CA's intermediate sign")
	flag.StringVar(&c.intermediateSignTTL, "intermediate-sign-ttl", "43800h", "TTL of Root CA's intermediate sign")

	flag.StringVar(&c.intermediateRole, "intermediate-role", "", "Role for intermediate CA")
	flag.StringVar(&c.intermediateRoleAllowedDomains, "intermediate-role-allowed-domains", "", "Allowed domains of role for intermediate CA")
	flag.BoolVar(&c.intermediateRoleAllowSubdomains, "intermediate-role-allow-subdomains", false, "Allow subdomains of role for intermediate CA")
	flag.StringVar(&c.intermediateRoleMaxTTL, "intermediate-role-max-ttl", "720h", "Max TTL of role for intermediate CA")
	flag.Parse()

	return c
}

func (c *config) url() string {
	return c.vaultScheme + "://" + c.vaultHost
}

/*
	Vault specific
*/

func VaultSetup(c *config) error {
	client := http.DefaultClient // @TODO
	err := createPKI(c, client)
	if err != nil {
		return err
	}

	err = maxTTL(c, client)
	if err != nil {
		return err
	}

	err = rootCA(c, client)
	if err != nil {
		return err
	}

	err = intermediatePKI(c, client)
	if err != nil {
		return err
	}

	err = intermediateMaxTTL(c, client)
	if err != nil {
		return err
	}

	csr, err := intermediateCA(c, client)
	if err != nil {
		return err
	}

	cert, err := intermediateSignCA(c, client, csr)
	if err != nil {
		return err
	}

	err = intermediateSignCertificate(c, client, cert)
	if err != nil {
		return err
	}

	err = createRole(c, client)
	if err != nil {
		return err
	}

	return nil
}

// Add Vault PKI to secret engines
// curl --header "X-Vault-Token: ..." \
//    --request POST \
//    --data '{"type":"pki"}' \
//    https://127.0.0.1:8200/v1/sys/mounts/pki
func createPKI(c *config, client *http.Client) error {
	body := map[string]string{
		"type": "pki",
	}
	bodyjson, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", c.url()+"/v1/sys/mounts/"+c.rootMount, bytes.NewBuffer(bodyjson))
	if err != nil {
		return err
	}

	_, err = requester(c, client, req)
	return err
}

// Set PKI maximum TTL
// curl --header "X-Vault-Token: ..." \
//    --request POST \
//    --data '{"max_lease_ttl":"87600h"}' \
//    https://127.0.0.1:8200/v1/sys/mounts/pki/tune
func maxTTL(c *config, client *http.Client) error {
	body := map[string]string{
		"max_lease_ttl": c.rootMaxLeaseTTL,
	}
	bodyjson, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", c.url()+"/v1/sys/mounts/"+c.rootMount+"/tune", bytes.NewBuffer(bodyjson))
	if err != nil {
		return err
	}

	_, err = requester(c, client, req)
	return err
}

// Create root CA for PKI
// $ tee payload.json <<EOF
// {
//   "common_name": "example.com",
//   "ttl": "87600h"
// }
// EOF

// $ curl --header "X-Vault-Token: ..." \
//        --request POST \
//        --data @payload.json \
//        https://127.0.0.1:8200/v1/pki/root/generate/internal \
//        | jq -r ".data.certificate" > CA_cert.crt
func rootCA(c *config, client *http.Client) error {
	body := map[string]string{
		"common_name": c.rootCommonName,
		"ttl":         c.rootTTL,
	}
	bodyjson, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", c.url()+"/v1/"+c.rootMount+"/root/generate/internal", bytes.NewBuffer(bodyjson))
	if err != nil {
		return err
	}

	_, err = requester(c, client, req)
	return err
}

// Create intermediate PKI
// $ curl --header "X-Vault-Token: ..." \
//        --request POST \
//        --data '{"type":"pki"}' \
//        https://127.0.0.1:8200/v1/sys/mounts/pki_int
func intermediatePKI(c *config, client *http.Client) error {
	body := map[string]string{
		"type": "pki",
	}
	bodyjson, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", c.url()+"/v1/sys/mounts/"+c.intermediateMount, bytes.NewBuffer(bodyjson))
	if err != nil {
		return err
	}

	_, err = requester(c, client, req)
	return err
}

// Set intermediate PKI max TTL
// $ curl --header "X-Vault-Token: ..." \
//        --request POST \
//        --data '{"max_lease_ttl":"43800h"}' \
//        https://127.0.0.1:8200/v1/sys/mounts/pki_int/tune
func intermediateMaxTTL(c *config, client *http.Client) error {
	body := map[string]string{
		"max_lease_ttl": c.intermediateMaxLeaseTTL,
	}
	bodyjson, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", c.url()+"/v1/sys/mounts/"+c.intermediateMount+"/tune", bytes.NewBuffer(bodyjson))
	if err != nil {
		return err
	}

	_, err = requester(c, client, req)
	return err
}

// Create intermediate CA
// $ tee payload-int.json <<EOF
// {
//   "common_name": "example.com Intermediate Authority",
//   "ttl": "43800h"
// }
// EOF

// $ curl --header "X-Vault-Token: ..." \
//        --request POST \
//        --data @payload-int.json \
//        https://127.0.0.1:8200/v1/pki_int/intermediate/generate/internal | jq
func intermediateCA(c *config, client *http.Client) (string, error) {
	body := map[string]string{
		"common_name": c.intermediateCommonName,
		"ttl":         c.intermediateTTL,
	}
	bodyjson, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", c.url()+"/v1/"+c.intermediateMount+"/intermediate/generate/internal", bytes.NewBuffer(bodyjson))
	if err != nil {
		return "", err
	}

	resp, err := requester(c, client, req)
	if err != nil {
		return "", err
	}

	var result map[string]interface{}
	json.Unmarshal(resp, &result)
	if data, k := result["data"]; k {
		if dataMap, ok := data.(map[string]interface{}); ok {
			if csr, okCSR := dataMap["csr"]; okCSR {
				return csr.(string), nil
			}
		}
	}

	return "", errors.New("csr not found")
}

// Sign intermediate CSR
// $ tee payload-int-cert.json <<EOF
// {
//   "csr": "...",
//   "format": "pem_bundle",
//   "ttl": "43800h"
// }
// EOF

// $ curl --header "X-Vault-Token: ..." \
//        --request POST \
//        --data @payload-int-cert.json \
//        https://127.0.0.1:8200/v1/pki/root/sign-intermediate | jq
func intermediateSignCA(c *config, client *http.Client, csr string) (string, error) {
	body := map[string]string{
		"csr":    csr,
		"format": c.intermediateSignFormat,
		"ttl":    c.intermediateSignTTL,
	}
	bodyjson, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", c.url()+"/v1/"+c.rootMount+"/root/sign-intermediate", bytes.NewBuffer(bodyjson))
	if err != nil {
		return "", err
	}

	resp, err := requester(c, client, req)
	if err != nil {
		return "", err
	}

	var result map[string]interface{}
	json.Unmarshal(resp, &result)
	if data, k := result["data"]; k {
		if dataMap, ok := data.(map[string]interface{}); ok {
			if certificate, okCertificate := dataMap["certificate"]; okCertificate {
				return certificate.(string), nil
			}
		}
	}

	return "", errors.New("certifiacte not found")
}

// Sign intermediate Certification
// $ tee payload-signed.json <<EOF
// {
//   "certificate": "..."
// }
// EOF

// $ curl --header "X-Vault-Token: ..." \
//         --request POST \
//         --data @payload-signed.json \
//         https://127.0.0.1:8200/v1/pki_int/intermediate/set-signed
func intermediateSignCertificate(c *config, client *http.Client, certificate string) error {
	body := map[string]string{
		"certificate": certificate,
	}
	bodyjson, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", c.url()+"/v1/"+c.intermediateMount+"/intermediate/set-signed", bytes.NewBuffer(bodyjson))
	if err != nil {
		return err
	}

	_, err = requester(c, client, req)
	return err
}

// Create role for pki_int
// $ tee payload-role.json <<EOF
// {
//   "allowed_domains": "example.com",
//   "allow_subdomains": true,
//   "max_ttl": "720h"
// }
// EOF

// $ curl --header "X-Vault-Token: ..." \
//        --request POST \
//        --data @payload-role.json \
//        https://127.0.0.1:8200/v1/pki_int/roles/example-dot-com
func createRole(c *config, client *http.Client) error {
	body := map[string]interface{}{
		"allowed_domains":  c.intermediateRoleAllowedDomains,
		"allow_subdomains": c.intermediateRoleAllowSubdomains,
		"max_ttl":          c.intermediateRoleMaxTTL,
	}
	bodyjson, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", c.url()+"/v1/"+c.intermediateMount+"/roles/"+c.intermediateRole, bytes.NewBuffer(bodyjson))
	if err != nil {
		return err
	}

	_, err = requester(c, client, req)
	return err
}

func requester(c *config, client *http.Client, req *http.Request) ([]byte, error) {
	req.Header.Add("X-Vault-Token", c.vaultToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode > 299 {

		return content, errors.New(string(content))
	}

	return content, nil
}

// Disable Secret engine @NOTE: only for test
// $ curl \
//     --header "X-Vault-Token: ..." \
//     --request DELETE \
//     http://127.0.0.1:8200/v1/sys/mounts/my-mount
func disableSecretEngine(c *config, client *http.Client, mount string) error {
	req, err := http.NewRequest("DELETE", c.url()+"/v1/sys/mounts/"+mount, nil)
	if err != nil {
		return err
	}

	_, err = requester(c, client, req)
	return err
}
