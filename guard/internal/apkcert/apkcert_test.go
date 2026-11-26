package apkcert

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func generateTestCertDER(t *testing.T, isCA bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Sandbox Work Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func buildTestV1APK(t *testing.T, certDER []byte) []byte {
	t.Helper()
	sd := pkcs7SignedData{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true},
		EncapContentInfo: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certDER},
		SignerInfos:      asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true},
	}
	sdBytes, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatal(err)
	}
	ci := pkcs7ContentInfo{
		ContentType: oidPKCS7SignedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdBytes},
	}
	pkcs7DER, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("META-INF/CERT.RSA")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(pkcs7DER); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractAPKCertSHA256_V2AndV1(t *testing.T) {
	certDER := generateTestCertDER(t, false)
	sum := sha256.Sum256(certDER)
	want := hex.EncodeToString(sum[:])

	// Test APK v2 signing block extraction
	v2APK, err := BuildV2SignedTestAPK(certDER)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	v2Path := filepath.Join(dir, "v2.apk")
	if err := os.WriteFile(v2Path, v2APK, 0600); err != nil {
		t.Fatal(err)
	}
	gotV2, err := ExtractPrimaryCertSHA256(v2Path)
	if err != nil {
		t.Fatalf("v2 extract error: %v", err)
	}
	if gotV2 != want {
		t.Fatalf("v2 cert mismatch: got %s want %s", gotV2, want)
	}

	// Test APK v1 JAR PKCS#7 extraction
	v1APK := buildTestV1APK(t, certDER)
	v1Path := filepath.Join(dir, "v1.apk")
	if err := os.WriteFile(v1Path, v1APK, 0600); err != nil {
		t.Fatal(err)
	}
	gotV1, err := ExtractPrimaryCertSHA256(v1Path)
	if err != nil {
		t.Fatalf("v1 extract error: %v", err)
	}
	if gotV1 != want {
		t.Fatalf("v1 cert mismatch: got %s want %s", gotV1, want)
	}

	// Reject garbage DER in V2 signing block.
	badV2, err := BuildV2SignedTestAPK([]byte("not-a-valid-x509-cert"))
	if err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(dir, "bad.apk")
	if err := os.WriteFile(badPath, badV2, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractAPKCertSHA256s(badPath); err == nil {
		t.Fatal("expected invalid DER certificate to be rejected")
	}

	// Verify V1 PKCS#7 chain with both CA cert and leaf cert prefers the leaf cert.
	caDER := generateTestCertDER(t, true)
	chainBytes := append(append([]byte(nil), caDER...), certDER...)
	chainPath := filepath.Join(dir, "chain.apk")
	if err := os.WriteFile(chainPath, buildTestV1APK(t, chainBytes), 0600); err != nil {
		t.Fatal(err)
	}
	gotChain, err := ExtractPrimaryCertSHA256(chainPath)
	if err != nil {
		t.Fatalf("v1 chain extract error: %v", err)
	}
	if gotChain != want {
		t.Fatalf("v1 chain expected leaf cert %s, got %s", want, gotChain)
	}
}
