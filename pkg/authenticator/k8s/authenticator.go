package k8s

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/fullsailor/pkcs7"
	"go.opentelemetry.io/otel"

	"github.com/cyberark/conjur-authn-k8s-client/pkg/access_token"
	"github.com/cyberark/conjur-authn-k8s-client/pkg/authenticator/common"
	"github.com/cyberark/conjur-authn-k8s-client/pkg/log"
	"github.com/cyberark/conjur-authn-k8s-client/pkg/utils"
	"github.com/cyberark/conjur-opentelemetry-tracer/pkg/trace"
)

var oidExtensionSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
var bufferTime = 30 * time.Second

// Authenticator contains the configuration and client
// for the authentication connection to Conjur
type Authenticator struct {
	client      *http.Client
	privateKey  *rsa.PrivateKey
	accessToken access_token.AccessToken
	config      *Config
	PublicCert  *x509.Certificate
}

const (
	nameTypeEmail = 1
	nameTypeDNS   = 2
	nameTypeURI   = 6
	nameTypeIP    = 7
)

// NewWithAccessToken creates a new authenticator instance from a given access token
func NewWithAccessToken(config Config, accessToken access_token.AccessToken) (*Authenticator, error) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, log.RecordedError(log.CAKC030, err)
	}

	client, err := common.NewHTTPSClient(config.Common.SSLCertificate, nil, nil)
	if err != nil {
		return nil, err
	}

	return &Authenticator{
		client:      client,
		privateKey:  signingKey,
		accessToken: accessToken,
		config:      &config,
	}, nil
}

// GetAccessToken is getter for accessToken
func (auth *Authenticator) GetAccessToken() access_token.AccessToken {
	return auth.accessToken
}

// Authenticate sends Conjur an authenticate request and writes the response
// to the token file (after decrypting it if needed). It also manages state of
// certificates.
// @deprecated Use AuthenticateWithContext instead
func (auth *Authenticator) Authenticate() error {
	return auth.AuthenticateWithContext(context.TODO())
}

func (auth *Authenticator) AuthenticateWithContext(ctx context.Context) error {
	log.Info(log.CAKC040, auth.config.Common.Username)

	tr := trace.NewOtelTracer(otel.Tracer("conjur-authn-k8s-client"))
	spanCtx, span := tr.Start(ctx, "Authenticate")
	defer span.End()

	err := auth.loginIfNeeded(spanCtx, tr)
	if err != nil {
		span.RecordErrorAndSetStatus(err)
		span.End()
		return err
	}

	authenticationResponse, err := auth.sendAuthenticationRequest(spanCtx, tr)
	if err != nil {
		span.RecordErrorAndSetStatus(err)
		span.End()
		return err
	}

	parsedResponse, err := auth.parseAuthenticationResponse(spanCtx, tr, authenticationResponse)
	if err != nil {
		span.RecordErrorAndSetStatus(err)
		span.End()
		return err
	}

	err = auth.accessToken.Write(parsedResponse)
	if err != nil {
		return err
	}

	log.Info(log.CAKC035)
	return nil
}

// generateCSR prepares the CSR
func (auth *Authenticator) generateCSR(commonName string) ([]byte, error) {
	sanURIString, err := generateSANURI(auth.config.PodNamespace, auth.config.PodName)
	sanURI, err := url.Parse(sanURIString)
	if err != nil {
		return nil, err
	}

	subj := pkix.Name{
		CommonName: commonName,
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	subjectAltNamesValue, err := marshalSANs(nil, nil, nil, []*url.URL{
		sanURI,
	})
	if err != nil {
		return nil, err
	}

	extSubjectAltName := pkix.Extension{
		Id:       oidExtensionSubjectAltName,
		Critical: false,
		Value:    subjectAltNamesValue,
	}
	template.ExtraExtensions = []pkix.Extension{extSubjectAltName}

	return x509.CreateCertificateRequest(rand.Reader, &template, auth.privateKey)
}

// login sends Conjur a CSR and verifies that the client cert is
// successfully retrieved
func (auth *Authenticator) login(ctx context.Context, tracer trace.Tracer) error {

	log.Debug(log.CAKC041, auth.config.Common.Username)

	ctx, span := tracer.Start(ctx, "Generate CSR")
	csrRawBytes, err := auth.generateCSR(auth.config.Common.Username.Suffix)

	csrBytes := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrRawBytes,
	})
	span.End()

	req, err := LoginRequest(ctx, auth.config.Common.URL, auth.config.ConjurVersion, csrBytes, auth.config.Common.Username.Prefix)
	if err != nil {
		return err
	}

	_, span = tracer.Start(ctx, "Send login request")
	resp, err := auth.client.Do(req)
	if err != nil {
		span.RecordErrorAndSetStatus(err)
		span.End()
		return log.RecordedError(log.CAKC028, err)
	}
	span.End()

	err = utils.ValidateResponse(resp)
	if err != nil {
		return log.RecordedError(log.CAKC029, err)
	}

	_, span = tracer.Start(ctx, "Wait for cert file")
	// Ensure client certificate exists before attempting to read it, with a tolerance
	// for small delays
	err = utils.WaitForFile(
		auth.config.Common.ClientCertPath,
		auth.config.Common.ClientCertRetryCountLimit,
	)
	if err != nil {
		// The response code was changed from 200 to 202 in the same Conjur version
		// that started writing the cert injection logs to the client. Verifying that
		// the response code is 202 will verify that we look for the log file only
		// if we expect it to be there
		if resp.StatusCode == 202 {
			injectClientCertError := consumeInjectClientCertError(auth.config.InjectCertLogPath)
			if injectClientCertError != "" {
				log.Error(log.CAKC055, injectClientCertError)
			}
		}
		span.RecordErrorAndSetStatus(err)
		span.End()
		return err
	}
	span.End()

	_, span = tracer.Start(ctx, "Load cert file")
	// load client cert
	certPEMBlock, err := ioutil.ReadFile(auth.config.Common.ClientCertPath)
	if err != nil {
		span.RecordErrorAndSetStatus(err)
		span.End()

		if os.IsNotExist(err) {
			return log.RecordedError(log.CAKC011, auth.config.Common.ClientCertPath)
		}

		return log.RecordedError(log.CAKC012, err)
	}
	log.Debug(log.CAKC049, auth.config.Common.ClientCertPath)

	certDERBlock, certPEMBlock := pem.Decode(certPEMBlock)
	cert, err := x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		return log.RecordedError(log.CAKC013, auth.config.Common.ClientCertPath, err)
		span.RecordErrorAndSetStatus(err)
		span.End()

		return log.RecordedError(log.CAKC013, auth.config.Common.ClientCertPath, err)
	}

	auth.PublicCert = cert
	span.End()

	// clean up the client cert so it's only available in memory
	os.Remove(auth.config.Common.ClientCertPath)
	log.Debug(log.CAKC050)

	return nil
}

// IsLoggedIn returns true if we are logged in (have a cert)
func (auth *Authenticator) IsLoggedIn() bool {
	return auth.PublicCert != nil
}

// isCertExpired returns true if certificate is expired or close to expiring
func (auth *Authenticator) isCertExpired() bool {
	certExpiresOn := auth.PublicCert.NotAfter.UTC()
	currentDate := time.Now().UTC()

	log.Debug(log.CAKC042, certExpiresOn)
	log.Debug(log.CAKC043, currentDate)
	log.Debug(log.CAKC044, bufferTime)

	return currentDate.Add(bufferTime).After(certExpiresOn)
}

// loginIfNeeded checks if we need to send a login request to Conjur and sends
// one if needed
func (auth *Authenticator) loginIfNeeded(ctx context.Context, tracer trace.Tracer) error {
	if !auth.IsLoggedIn() {
		log.Debug(log.CAKC039)

		if err := auth.login(ctx, tracer); err != nil {
			return log.RecordedError(log.CAKC015)
		}

		log.Debug(log.CAKC036)
	}

	if auth.isCertExpired() {
		log.Debug(log.CAKC038)

		if err := auth.login(ctx, tracer); err != nil {
			return err
		}

		log.Debug(log.CAKC037)
	}

	return nil
}

// sendAuthenticationRequest reads the cert from memory and uses it to send
// an authentication request to the Conjur server. It also validates the response
// code before returning its body
func (auth *Authenticator) sendAuthenticationRequest(ctx context.Context, tracer trace.Tracer) ([]byte, error) {
	ctx, span := tracer.Start(ctx, "Send authentication request")
	defer span.End()

	privDer := x509.MarshalPKCS1PrivateKey(auth.privateKey)
	keyPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDer})

	certPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: auth.PublicCert.Raw})

	client, err := common.NewHTTPSClient(auth.config.Common.SSLCertificate, certPEMBlock, keyPEMBlock)
	if err != nil {
		span.RecordErrorAndSetStatus(err)
		return nil, err
	}

	req, err := AuthenticateRequest(
		ctx,
		auth.config.Common.URL,
		auth.config.ConjurVersion,
		auth.config.Common.Account,
		auth.config.Common.Username.FullUsername,
	)
	if err != nil {
		span.RecordErrorAndSetStatus(err)
		return nil, err
	}

	log.Debug(log.CAKC069, AuthnType)
	resp, err := client.Do(req)
	if err != nil {
		span.RecordErrorAndSetStatus(err)
		return nil, log.RecordedError(log.CAKC027, err)
	}

	err = utils.ValidateResponse(resp)
	if err != nil {
		span.RecordErrorAndSetStatus(err)
		return nil, err
	}

	return utils.ReadResponseBody(resp)
}

// parseAuthenticationResponse takes the response from the Authenticate
// request, decrypts if needed, and returns it
func (auth *Authenticator) parseAuthenticationResponse(ctx context.Context, tracer trace.Tracer, response []byte) ([]byte, error) {
	_, span := tracer.Start(ctx, "Parse authentication response")
	defer span.End()

	var content []byte
	var err error

	// Token is only encrypted in Conjur v4
	if auth.config.ConjurVersion == "4" {
		content, err = decodeFromPEM(response, auth.PublicCert, auth.privateKey)
		if err != nil {
			span.RecordErrorAndSetStatus(err)
			return nil, log.RecordedError(log.CAKC020)
		}
	} else if auth.config.ConjurVersion == "5" {
		content = response
	}

	return content, nil
}

// generateSANURI returns the formatted uri(SPIFFEE format for now) for the certificate.
func generateSANURI(namespace, podname string) (string, error) {
	if namespace == "" || podname == "" {
		return "", log.RecordedError(log.CAKC008, namespace, podname)
	}
	return fmt.Sprintf("spiffe://cluster.local/namespace/%s/podname/%s", namespace, podname), nil
}

func marshalSANs(dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL) ([]byte, error) {
	var rawValues []asn1.RawValue
	for _, name := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeDNS, Class: asn1.ClassContextSpecific, Bytes: []byte(name)})
	}
	for _, email := range emailAddresses {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeEmail, Class: asn1.ClassContextSpecific, Bytes: []byte(email)})
	}
	for _, rawIP := range ipAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeIP, Class: asn1.ClassContextSpecific, Bytes: ip})
	}
	for _, uri := range uris {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeURI, Class: asn1.ClassContextSpecific, Bytes: []byte(uri.String())})
	}
	return asn1.Marshal(rawValues)
}

func decodeFromPEM(PEMBlock []byte, PublicCert *x509.Certificate, privateKey crypto.PrivateKey) ([]byte, error) {
	var decodedPEM []byte

	tokenDerBlock, _ := pem.Decode(PEMBlock)
	p7, err := pkcs7.Parse(tokenDerBlock.Bytes)
	if err != nil {
		return nil, log.RecordedError(log.CAKC026, err)
	}

	decodedPEM, err = p7.Decrypt(PublicCert, privateKey)
	if err != nil {
		return nil, log.RecordedError(log.CAKC025, err)
	}

	return decodedPEM, nil
}

func consumeInjectClientCertError(path string) string {
	// The log file will not exist in old Conjur versions
	err := utils.VerifyFileExists(path)
	if err != nil {
		log.Warn(log.CAKC056, path)
		return ""
	}

	content, err := ioutil.ReadFile(path)
	if err != nil {
		log.Error(log.CAKC053, path)
		return ""
	}

	log.Debug(log.CAKC057, path)
	err = os.Remove(path)
	if err != nil {
		log.Error(log.CAKC054, path)
	}

	return string(content)
}
