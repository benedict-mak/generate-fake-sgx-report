package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/elliptic"
	"crypto/ecdsa"
	"encoding/pem"
	"encoding/json"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"time"
	"crypto/sha256"
	"net/url"
	"github.com/edgelesssys/ego/enclave"
	"encoding/binary"
	
)

// attestationProviderURL is the URL of the attestation provider
const attestationProviderURL = "https://shareduks.uks.attest.azure.net"

func ShowAndValidateSGXReport(report []byte) {
	origin_report_byte := report

	report_version := int32(binary.LittleEndian.Uint32(origin_report_byte[0:4]))
	fmt.Println("Report Version", report_version)

	report_type := int32(binary.LittleEndian.Uint32(origin_report_byte[4:8]))
	fmt.Println("Report Type", report_type)	

	report_size := int64(binary.LittleEndian.Uint64(origin_report_byte[8:16]))
	fmt.Println("Report Size", report_size)	

	report_array := origin_report_byte[16:]
	fmt.Println("Actual Report Size", binary.Size(report_array))

	quote_version := int16(binary.LittleEndian.Uint16(report_array[0:2]))
	fmt.Println("quote_version", quote_version)

	quote_sign_type := int16(binary.LittleEndian.Uint16(report_array[2:4]))
	fmt.Println("quote_sign_type", quote_sign_type)

	quote_epid_group_id_1 := uint8(report_array[4])
	quote_epid_group_id_2 := uint8(report_array[5])
	quote_epid_group_id_3 := uint8(report_array[6])
	quote_epid_group_id_4 := uint8(report_array[7])
	fmt.Println("quote_epid_group_id", quote_epid_group_id_1, quote_epid_group_id_2, quote_epid_group_id_3, quote_epid_group_id_4)

	quote_qe_svn := int16(binary.LittleEndian.Uint16(report_array[8:10]))
	fmt.Println("quote_qe_svn", quote_qe_svn)

	quote_pce_svn := int16(binary.LittleEndian.Uint16(report_array[10:12]))
	fmt.Println("quote_pce_svn", quote_pce_svn)

	quote_xeid := int32(binary.LittleEndian.Uint32(report_array[12:16]))
	fmt.Println("quote_xeid", quote_xeid)

	quote_basename := report_array[16:48]
	fmt.Println("quote_basename", quote_basename)

	quote_cpu_svn := report_array[48:58]
	fmt.Println("quote_cpu_svn", quote_cpu_svn)

	quote_misc_select := int32(binary.LittleEndian.Uint32(report_array[58:62]))
	fmt.Println("quote_misc_select", quote_misc_select)

	quote_mr_enclave := hex.EncodeToString(report_array[112:144])
	fmt.Println("quote_mr_enclave", quote_mr_enclave)

	quote_mr_signer := hex.EncodeToString(report_array[176:208])
	fmt.Println("quote_mr_signer", quote_mr_signer)

	quote_prod_id := int16(binary.LittleEndian.Uint16(report_array[304:306]))
	fmt.Println("quote_prod_id", quote_prod_id)

	quote_report_data := hex.EncodeToString(report_array[368:432])
	fmt.Println("quote_report_data", quote_report_data)	

	quote_signature_length := int32(binary.LittleEndian.Uint32(report_array[432:436]))
	fmt.Println("quote_signature_length", quote_signature_length)

	quote_auth_data := report_array[436:1012]
	
	quote_auth_data_signature_r := new(big.Int).SetBytes(quote_auth_data[0:32])
	quote_auth_data_signature_s := new(big.Int).SetBytes(quote_auth_data[32:64])
	fmt.Println("quote_auth_data_signature", quote_auth_data_signature_r, quote_auth_data_signature_s)

	quote_auth_data_attestation_key_x := quote_auth_data[64:96]
	fmt.Println("quote_auth_data_attestation_key_x", quote_auth_data_attestation_key_x)

	quote_auth_data_attestation_key_y := quote_auth_data[96:128]
	fmt.Println("quote_auth_data_attestation_key_y", quote_auth_data_attestation_key_y)
	
	quote_auth_data_attestation_key := ecdsa.PublicKey{elliptic.P256(), new(big.Int).SetBytes(quote_auth_data_attestation_key_x), new(big.Int).SetBytes(quote_auth_data_attestation_key_y)}

	fmt.Println("quote_auth_data_attestation_key", quote_auth_data_attestation_key)

	quote_auth_data_qe_report_body := quote_auth_data[128:512]
	fmt.Println("quote_auth_data_qe_report_body", hex.EncodeToString(quote_auth_data_qe_report_body))

	z := new(big.Int)
	z.SetBytes(quote_auth_data[512:544])
	quote_auth_data_qe_report_body_signature_r := z
	fmt.Println("quote_auth_data_qe_report_body_signature_r", quote_auth_data_qe_report_body_signature_r)

	y := new(big.Int)
	y.SetBytes(quote_auth_data[544:576])
	quote_auth_data_qe_report_body_signature_s := y
	fmt.Println("quote_auth_data_qe_report_body_signature_s", quote_auth_data_qe_report_body_signature_s)

	qe_auth_data_size := int16(binary.LittleEndian.Uint16(report_array[1012:1014]))
	fmt.Println("qe_auth_data_size", qe_auth_data_size)

	qe_auth_data := report_array[1014:1014+qe_auth_data_size]
	fmt.Println("qe_auth_data", qe_auth_data)

	qe_cert_data_type := int16(binary.LittleEndian.Uint16(report_array[1014+qe_auth_data_size:1014+qe_auth_data_size+2]))
	fmt.Println("qe_cert_data_type", qe_cert_data_type)

	qe_cert_data_size := int32(binary.LittleEndian.Uint32(report_array[1014+qe_auth_data_size+2:1014+qe_auth_data_size+6]))
	fmt.Println("qe_cert_data_size", qe_cert_data_size)

	qe_cert_data := report_array[1014+qe_auth_data_size+6:]
	// fmt.Println("qe_cert_data", hex.EncodeToString(qe_cert_data))

	leaf_match := bytes.Index(qe_cert_data[:], []byte("-----END CERTIFICATE-----\n"))+len("-----END CERTIFICATE-----\n")

	fmt.Println("Leaf certificate", hex.EncodeToString(qe_cert_data[0:leaf_match]))

	intermediate_match := bytes.Index(qe_cert_data[leaf_match:], []byte("-----END CERTIFICATE-----\n"))+len("-----END CERTIFICATE-----\n")

	fmt.Println("Intermediate certificate", hex.EncodeToString(qe_cert_data[leaf_match:leaf_match+intermediate_match]))

	root_match := bytes.Index(qe_cert_data[leaf_match+intermediate_match:], []byte("-----END CERTIFICATE-----\n"))+len("-----END CERTIFICATE-----\n")

	fmt.Println("Root certificate", hex.EncodeToString(qe_cert_data[leaf_match+intermediate_match:leaf_match+intermediate_match+root_match]))


	leaf_block, _ := pem.Decode([]byte(qe_cert_data[0:leaf_match]))
	if leaf_block == nil {
        fmt.Errorf("failed to parse certificate PEM")
    }
    fmt.Println("leaf_block", leaf_block)

    leaf_cert, _ := x509.ParseCertificate(leaf_block.Bytes)
    leaf_publickey := leaf_cert.PublicKey.(*ecdsa.PublicKey)
    fmt.Println("leaf_publickey", leaf_publickey)

    intermediate_block, _ := pem.Decode([]byte(qe_cert_data[leaf_match:leaf_match+intermediate_match]))
	if intermediate_block == nil {
        fmt.Errorf("failed to parse certificate PEM")
    }
    fmt.Println("intermediate_block", intermediate_block)

    root_block, _ := pem.Decode([]byte(qe_cert_data[leaf_match+intermediate_match:leaf_match+intermediate_match+root_match]))
	if root_block == nil {
        fmt.Errorf("failed to parse certificate PEM")
    }
    fmt.Println("root_block", root_block)

    root_cert, _ := x509.ParseCertificate(root_block.Bytes)
    root_publickey := root_cert.PublicKey.(*ecdsa.PublicKey)
    fmt.Println("root_publickey", root_publickey)

    root_pubkey_bytes, _ := x509.MarshalPKIXPublicKey(root_publickey)
    var pemPrivateBlock = &pem.Block{
	    Type:  "ECDSA PRIVATE KEY",
	    Bytes: root_pubkey_bytes,
	}
	fmt.Println("root_publickey_pem", pemPrivateBlock)

	intel_root_pubkey_string := []byte("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi71OiO\nSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlA==\n-----END PUBLIC KEY-----\n")
	intel_root_pubkey_block, _ := pem.Decode(intel_root_pubkey_string)
	if intel_root_pubkey_block == nil {
        fmt.Errorf("failed to parse certificate PEM")
    }
    fmt.Println("intel_root_pubkey_block", intel_root_pubkey_block)

    //Cehcking

    //Hash with PCK(QE report body) == QE report body signature
    quote_auth_data_qe_report_body_hash := sha256.Sum256(quote_auth_data_qe_report_body)
   	
   	fmt.Println(ecdsa.Verify(leaf_publickey, quote_auth_data_qe_report_body_hash[:] ,quote_auth_data_qe_report_body_signature_r, quote_auth_data_qe_report_body_signature_s))

   	//Assert SHA256 (attestation_key + qe_auth_data.data) == qe_report_body.report_data[0..32]
   	hash_attestation_key_qe_auth_data := sha256.Sum256(append(append(quote_auth_data_attestation_key_x, quote_auth_data_attestation_key_y...), qe_auth_data...))
	fmt.Println(bytes.Compare(hash_attestation_key_qe_auth_data[:],quote_auth_data_qe_report_body[320:352]))

   	//Hash with attestation_key(sgx_quote) == quote_auth_data signature
   	quote_hash := sha256.Sum256(report_array[0:432])
   	fmt.Println(ecdsa.Verify(&quote_auth_data_attestation_key, quote_hash[:] ,quote_auth_data_signature_r, quote_auth_data_signature_s))
}

func main() {
	cert, _ := createCertificate()
	hash := sha256.Sum256(cert)
	fmt.Printf("🆗 Generated certificate with hash %x\n\n", hash)

	report, _ := enclave.GetRemoteReport(hash[:])
	
	// ShowAndValidateSGXReport(report)

	fmt.Println("0. Normal RA report submission")
	origin_report_byte99 := append([]byte(nil), report[:]...)
	fmt.Println("origin_report_byte99", len(origin_report_byte99))
	token99, err99 := CreateAzureAttestationToken(origin_report_byte99, cert, attestationProviderURL)
	fmt.Println(err99)
	fmt.Println("🆗 Got azure token with length", len(token99), "\n\n")


	fmt.Println("1. Attempt to sumbit a RA report without certs")
	origin_report_byte0 := append([]byte(nil), report[0:16+1014+32]...)
	fmt.Println("origin_report_byte0", len(origin_report_byte0))
	token0, err0 := CreateAzureAttestationToken(origin_report_byte0, cert, attestationProviderURL)
	fmt.Println(err0)
	fmt.Println("🆗 Got azure token with length", len(token0), "\n\n")


	fmt.Println("2. Attempt to sumbit a RA report with new certs and new signature")
   	origin_report_byte1 := append([]byte(nil), report[:]...)
   	report_array1 := origin_report_byte1[16:]

	rootCert, rootCertPEM, rootKey := GenCARoot()
	DCACert, DCACertPEM, DCAKey := GenDCA(rootCert, rootKey)
	_, ServerPEM, ServerKey := GenServerCert(DCACert, DCAKey)
	qe_cert_data1 := append(append(ServerPEM, DCACertPEM...), rootCertPEM...)

	fmt.Println("qe_cert_data1", hex.EncodeToString(qe_cert_data1))
	fmt.Println("qe_cert_data1_length", len(qe_cert_data1))

	qe_cert_data_size1 := make([]byte, 4)
	binary.LittleEndian.PutUint32(qe_cert_data_size1, uint32(len(qe_cert_data1)))
	fmt.Println("qe_cert_data_size1", qe_cert_data_size1)

	quote_auth_data1 := report_array1[436:1012]

	quote_auth_data_qe_report_body1 := quote_auth_data1[128:512]

	quote_auth_data_qe_report_body_hash1 := sha256.Sum256(quote_auth_data_qe_report_body1)
	quote_auth_data_qe_report_body_signature_r1, quote_auth_data_qe_report_body_signature_s1, _ := ecdsa.Sign(rand.Reader, ServerKey, quote_auth_data_qe_report_body_hash1[:])


	new_report_size := make([]byte, 8)
	binary.LittleEndian.PutUint64(new_report_size, uint64(len(qe_cert_data1)+1014+32+6))
	fmt.Println("new_report_size", new_report_size)

	new_report := append([]byte(nil), origin_report_byte1[0:8]...)
	new_report = append(new_report, new_report_size...)
	new_report = append(new_report, report_array1[0:436]...)
	new_report = append(new_report, quote_auth_data1[0:512]...)
	new_report = append(new_report, quote_auth_data_qe_report_body_signature_r1.Bytes()...)
	new_report = append(new_report, quote_auth_data_qe_report_body_signature_s1.Bytes()...)
	new_report = append(new_report, report_array1[1012:1048]...)
	new_report = append(new_report, qe_cert_data_size1...)
	new_report = append(new_report, qe_cert_data1...)

	fmt.Println("new report length", len(new_report))

	ShowAndValidateSGXReport(new_report)

	token1, err1 := CreateAzureAttestationToken(new_report, cert, attestationProviderURL)
	fmt.Println(err1)
	fmt.Println("🆗 Got azure token with length", len(token1), "\n\n")


	fmt.Println("3. Attempt to sumbit a RA report with old intel cert and fake quote_auth_data_signature")
	origin_report_byte2 := append([]byte(nil), report[:]...)

	fake_signature_2 := make([]byte, 32)
	rand.Read(fake_signature_2)

	new_report1 := append([]byte(nil), origin_report_byte2[0:16+436]...)
	new_report1 = append(new_report1, fake_signature_2...)
	new_report1 = append(new_report1, fake_signature_2...)
	new_report1 = append(new_report1, origin_report_byte2[516:]...)

	ShowAndValidateSGXReport(new_report)

	token2, err2 := CreateAzureAttestationToken(new_report1, cert, attestationProviderURL)
	fmt.Println(err2)
	fmt.Println("🆗 Got azure token with length", len(token2), "\n\n")
	
}


func CreateAzureAttestationToken(report, data []byte, baseurl string) (string, error) {
	// Create attestation request struct.
	rtd := rtdata{Data: base64.RawURLEncoding.EncodeToString(data), DataType: "Binary"}
	attReq := attestOERequest{Report: base64.RawURLEncoding.EncodeToString(report), RuntimeData: rtd}

	// Parse url and add path.
	uri, err := url.Parse(baseurl)
	if err != nil {
		return "", err
	}
	path, err := url.Parse("/attest/OpenEnclave?api-version=2020-10-01")
	if err != nil {
		return "", err
	}
	uri = uri.ResolveReference(path)

	// Marshal request struct to JSON.
	jsonReq, err := json.Marshal(attReq)
	if err != nil {
		return "", err
	}

	// Create HTTP client skiping TLS certificate verification, since
	// the enclave does not have a set of Root CAs. There is no need
	// for a trusted connection.
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	client := http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	resp, err := client.Post(uri.String(), "application/json", bytes.NewReader(jsonReq))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Check response and return the token.
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("attestation request failed, attestation provider returned status code %v", resp.StatusCode)
	}
	body := new(attestationResponse)
	if err := json.NewDecoder(resp.Body).Decode(body); err != nil {
		return "", err
	}
	return body.Token, nil
}

type attestOERequest struct {
	Report      string `json:"report"`
	RuntimeData rtdata `json:"runtimeData"`
}

type rtdata struct {
	Data     string `json:"data"`
	DataType string `json:"dataType"`
}

type attestationResponse struct {
	Token string `json:"token"`
}


func createCertificate() ([]byte, crypto.PrivateKey) {
	template := &x509.Certificate{
		SerialNumber: &big.Int{},
		Subject:      pkix.Name{CommonName: "0.0.0.0"},
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("0.0.0.0")},
	}
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	return cert, priv
}


func genCert(template, parent *x509.Certificate, priv *ecdsa.PrivateKey, privateKey *ecdsa.PrivateKey) (*x509.Certificate, []byte) {
	publicKey := priv.Public()
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		panic("Failed to create certificate:" + err.Error())
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		panic("Failed to parse certificate:" + err.Error())
	}

	b := pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	certPEM := pem.EncodeToMemory(&b)

	return cert, certPEM
}

func GenCARoot() (*x509.Certificate, []byte, *ecdsa.PrivateKey) {
	var rootTemplate = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"US"},
			CommonName:   "intel.com",
		},
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	rootCert, rootPEM := genCert(&rootTemplate, &rootTemplate, priv, priv)
	return rootCert, rootPEM, priv
}

func GenDCA(RootCert *x509.Certificate, RootKey *ecdsa.PrivateKey) (*x509.Certificate, []byte, *ecdsa.PrivateKey) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	var DCATemplate = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"US"},
			CommonName:   "sign.intel.com",
		},
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
		MaxPathLen:            1,
	}
	DCACert, DCAPEM := genCert(&DCATemplate, RootCert, priv, RootKey)
	return DCACert, DCAPEM, priv
}

func GenServerCert(DCACert *x509.Certificate, DCAKey *ecdsa.PrivateKey) (*x509.Certificate, []byte, *ecdsa.PrivateKey) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	var ServerTemplate = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"US"},
			CommonName:   "server.intel.com",
		},
		NotBefore:      time.Now().Add(-10 * time.Second),
		NotAfter:       time.Now().AddDate(10, 0, 0),
		KeyUsage:       x509.KeyUsageCRLSign,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:           false,
		MaxPathLenZero: true,
	}

	ServerCert, ServerPEM := genCert(&ServerTemplate, DCACert, priv, DCAKey)
	return ServerCert, ServerPEM, priv

}