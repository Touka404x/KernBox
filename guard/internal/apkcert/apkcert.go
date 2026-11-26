package apkcert

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

const (
	apkSigBlockMagic = "APK Sig Block 42"
	apkSigV2ID       = uint32(0x7109871a)
	apkSigV3ID       = uint32(0xf05368c0)
	apkSigV31ID      = uint32(0x1b93ad61)
	maxSigBlockBytes = 16 << 20
	maxV1SigBytes    = 2 << 20
)

var (
	oidPKCS7SignedData  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
)

type x509CertificateASN1 struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	SignatureValue     asn1.BitString
}

type x509ExtensionASN1 struct {
	ID       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

type x509TBSCertificateASN1 struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	Issuer             asn1.RawValue
	Validity           asn1.RawValue
	Subject            asn1.RawValue
	PublicKeyInfo      asn1.RawValue
	IssuerUniqueID     asn1.BitString     `asn1:"optional,tag:1"`
	SubjectUniqueID    asn1.BitString     `asn1:"optional,tag:2"`
	Extensions         []x509ExtensionASN1 `asn1:"optional,explicit,tag:3"`
}

func isASN1Sequence(v asn1.RawValue) bool {
	return v.Class == asn1.ClassUniversal && v.Tag == asn1.TagSequence && v.IsCompound
}

// validateX509CertDER verifies X.509 DER structure using encoding/asn1 without
// pulling crypto/x509, math/big, or asymmetric signature packages into sandbox_guard.
func validateX509CertDER(der []byte) (bool, error) {
	if len(der) == 0 {
		return false, errors.New("empty certificate DER")
	}
	var cert x509CertificateASN1
	rest, err := asn1.Unmarshal(der, &cert)
	if err != nil {
		return false, err
	}
	if len(rest) != 0 {
		return false, errors.New("trailing data after X.509 certificate")
	}
	if !isASN1Sequence(cert.TBSCertificate) || !isASN1Sequence(cert.SignatureAlgorithm) {
		return false, errors.New("malformed X.509 outer sequence")
	}

	var tbs x509TBSCertificateASN1
	tbsRest, err := asn1.Unmarshal(cert.TBSCertificate.FullBytes, &tbs)
	if err != nil {
		return false, err
	}
	if len(tbsRest) != 0 {
		return false, errors.New("trailing data after TBSCertificate")
	}
	if tbs.SerialNumber.Class != asn1.ClassUniversal || tbs.SerialNumber.Tag != asn1.TagInteger {
		return false, errors.New("invalid X.509 serialNumber")
	}
	if !isASN1Sequence(tbs.SignatureAlgorithm) ||
		!isASN1Sequence(tbs.Issuer) ||
		!isASN1Sequence(tbs.Validity) ||
		!isASN1Sequence(tbs.Subject) ||
		!isASN1Sequence(tbs.PublicKeyInfo) {
		return false, errors.New("malformed X.509 TBSCertificate fields")
	}

	for _, ext := range tbs.Extensions {
		if !ext.ID.Equal(oidBasicConstraints) {
			continue
		}
		var bc struct {
			IsCA bool `asn1:"optional"`
		}
		if _, err := asn1.Unmarshal(ext.Value, &bc); err == nil && bc.IsCA {
			return true, nil
		}
	}
	return false, nil
}

// ExtractAPKCertSHA256s parses an APK file (v3/v2 APK Signing Block or v1 JAR PKCS#7)
// and returns lowercase hex SHA-256 digests of its signing certificates.
func ExtractAPKCertSHA256s(apkPath string) ([]string, error) {
	f, err := os.Open(apkPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("apk is not a regular file")
	}
	size := st.Size()
	if size < 22 {
		return nil, errors.New("file too small to be an APK")
	}

	if certs, ok, err := extractFromSigningBlock(f, size); err == nil && ok && len(certs) > 0 {
		return certs, nil
	}
	return extractFromV1JAR(f, size)
}

// ExtractPrimaryCertSHA256 returns the first/primary signer certificate SHA-256.
func ExtractPrimaryCertSHA256(apkPath string) (string, error) {
	certs, err := ExtractAPKCertSHA256s(apkPath)
	if err != nil {
		return "", err
	}
	if len(certs) == 0 {
		return "", errors.New("no signing certificate found in APK")
	}
	return certs[0], nil
}

func extractFromSigningBlock(r io.ReaderAt, fileSize int64) ([]string, bool, error) {
	cdOffset, err := findZipCDOffset(r, fileSize)
	if err != nil || cdOffset < 32 {
		return nil, false, err
	}
	var footer [24]byte
	if _, err := r.ReadAt(footer[:], cdOffset-24); err != nil {
		return nil, false, err
	}
	if string(footer[8:24]) != apkSigBlockMagic {
		return nil, false, nil
	}
	blockSizeEnd := binary.LittleEndian.Uint64(footer[0:8])
	if blockSizeEnd < 24 || blockSizeEnd > maxSigBlockBytes || int64(blockSizeEnd) > cdOffset-8 {
		return nil, false, errors.New("invalid APK signing block size")
	}
	blockStart := cdOffset - 8 - int64(blockSizeEnd)
	if blockStart < 0 {
		return nil, false, errors.New("invalid APK signing block start")
	}
	var header [8]byte
	if _, err := r.ReadAt(header[:], blockStart); err != nil {
		return nil, false, err
	}
	blockSizeStart := binary.LittleEndian.Uint64(header[:])
	if blockSizeStart != blockSizeEnd {
		return nil, false, errors.New("APK signing block header/footer size mismatch")
	}

	pairsLen := int(blockSizeEnd) - 24
	pairs := make([]byte, pairsLen)
	if _, err := r.ReadAt(pairs, blockStart+8); err != nil {
		return nil, false, err
	}

	var v31Certs, v3Certs, v2Certs []string
	for off := 0; off+12 <= len(pairs); {
		pairLen := binary.LittleEndian.Uint64(pairs[off : off+8])
		off += 8
		if pairLen < 4 || pairLen > uint64(len(pairs)-off) {
			break
		}
		id := binary.LittleEndian.Uint32(pairs[off : off+4])
		val := pairs[off+4 : off+int(pairLen)]
		off += int(pairLen)

		switch id {
		case apkSigV31ID:
			if c, err := parseV2V3Signers(val); err == nil && len(c) > 0 {
				v31Certs = append(v31Certs, c...)
			}
		case apkSigV3ID:
			if c, err := parseV2V3Signers(val); err == nil && len(c) > 0 {
				v3Certs = append(v3Certs, c...)
			}
		case apkSigV2ID:
			if c, err := parseV2V3Signers(val); err == nil && len(c) > 0 {
				v2Certs = append(v2Certs, c...)
			}
		}
	}
	switch {
	case len(v31Certs) > 0:
		return uniqueStrings(v31Certs), true, nil
	case len(v3Certs) > 0:
		return uniqueStrings(v3Certs), true, nil
	case len(v2Certs) > 0:
		return uniqueStrings(v2Certs), true, nil
	default:
		return nil, false, nil
	}
}

func findZipCDOffset(r io.ReaderAt, fileSize int64) (int64, error) {
	maxScan := int64(22 + 65535)
	if fileSize < maxScan {
		maxScan = fileSize
	}
	buf := make([]byte, maxScan)
	start := fileSize - maxScan
	if _, err := r.ReadAt(buf, start); err != nil {
		return 0, err
	}
	for i := len(buf) - 22; i >= 0; i-- {
		if binary.LittleEndian.Uint32(buf[i:i+4]) != 0x06054b50 {
			continue
		}
		commentLen := int64(binary.LittleEndian.Uint16(buf[i+20 : i+22]))
		if start+int64(i)+22+commentLen != fileSize {
			continue
		}
		cdOffset := binary.LittleEndian.Uint32(buf[i+16 : i+20])
		if cdOffset == 0xffffffff {
			return 0, errors.New("zip64 EOCD unsupported")
		}
		return int64(cdOffset), nil
	}
	return 0, errors.New("ZIP EOCD not found")
}

func readLenPrefixed(b []byte) ([]byte, []byte, error) {
	if len(b) < 4 {
		return nil, nil, errors.New("truncated length-prefixed field")
	}
	n := int(binary.LittleEndian.Uint32(b[:4]))
	if n < 0 || 4+n > len(b) {
		return nil, nil, errors.New("invalid length-prefixed field")
	}
	return b[4 : 4+n], b[4+n:], nil
}

func parseV2V3Signers(blockVal []byte) ([]string, error) {
	signersBytes, _, err := readLenPrefixed(blockVal)
	if err != nil {
		return nil, err
	}
	var hashes []string
	for len(signersBytes) > 0 {
		var signerBytes []byte
		signerBytes, signersBytes, err = readLenPrefixed(signersBytes)
		if err != nil {
			return nil, err
		}
		signedData, _, err := readLenPrefixed(signerBytes)
		if err != nil {
			return nil, err
		}
		// digests
		_, rest, err := readLenPrefixed(signedData)
		if err != nil {
			return nil, err
		}
		// certificates
		certsBytes, _, err := readLenPrefixed(rest)
		if err != nil {
			return nil, err
		}
		if len(certsBytes) == 0 {
			continue
		}
		certDER, _, err := readLenPrefixed(certsBytes)
		if err != nil {
			return nil, err
		}
		if _, err := validateX509CertDER(certDER); err != nil {
			return nil, fmt.Errorf("invalid signer cert DER: %w", err)
		}
		sum := sha256.Sum256(certDER)
		hashes = append(hashes, hex.EncodeToString(sum[:]))
	}
	return hashes, nil
}

type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type pkcs7SignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

func extractFromV1JAR(r io.ReaderAt, fileSize int64) ([]string, error) {
	zr, err := zip.NewReader(r, fileSize)
	if err != nil {
		return nil, err
	}
	var hashes []string
	for _, f := range zr.File {
		clean := path.Clean(f.Name)
		if !strings.HasPrefix(clean, "META-INF/") || strings.Count(clean, "/") != 1 {
			continue
		}
		upper := strings.ToUpper(clean)
		if !strings.HasSuffix(upper, ".RSA") && !strings.HasSuffix(upper, ".DSA") && !strings.HasSuffix(upper, ".EC") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		der, err := io.ReadAll(io.LimitReader(rc, maxV1SigBytes+1))
		_ = rc.Close()
		if err != nil || len(der) > maxV1SigBytes {
			continue
		}
		parsed, err := parsePKCS7Certs(der)
		if err != nil {
			continue
		}
		hashes = append(hashes, parsed...)
	}
	if len(hashes) == 0 {
		return nil, errors.New("no valid APK v1/v2/v3 signing certificate found")
	}
	return uniqueStrings(hashes), nil
}

func parsePKCS7Certs(der []byte) ([]string, error) {
	var ci pkcs7ContentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, err
	}
	if !ci.ContentType.Equal(oidPKCS7SignedData) {
		return nil, errors.New("not PKCS7 SignedData")
	}
	var sd pkcs7SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, err
	}
	var leafHashes, allHashes []string
	rest := sd.Certificates.Bytes
	for len(rest) > 0 {
		var rawCert asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &rawCert)
		if err != nil {
			return nil, err
		}
		isCA, err := validateX509CertDER(rawCert.FullBytes)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(rawCert.FullBytes)
		h := hex.EncodeToString(sum[:])
		allHashes = append(allHashes, h)
		if !isCA {
			leafHashes = append(leafHashes, h)
		}
	}
	if len(leafHashes) > 0 {
		return leafHashes, nil
	}
	return allHashes, nil
}

// BuildV2SignedTestAPK creates a minimal ZIP with an APK v2 Signing Block (used in tests).
func BuildV2SignedTestAPK(certDER []byte) ([]byte, error) {
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	w, err := zw.Create("AndroidManifest.xml")
	if err != nil {
		return nil, err
	}
	if _, err := w.Write([]byte("manifest")); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	rawZip := zipBuf.Bytes()
	cdOffset, err := findZipCDOffset(bytes.NewReader(rawZip), int64(len(rawZip)))
	if err != nil {
		return nil, err
	}
	// Construct minimal v2 signer block:
	// certEntry = len(certDER) + certDER
	certEntry := lenPrefixed(certDER)
	// signedData = lenPrefixed(digests=empty) + lenPrefixed(certs=certEntry) + lenPrefixed(attrs=empty)
	var signedData bytes.Buffer
	signedData.Write(lenPrefixed(nil))
	signedData.Write(lenPrefixed(certEntry))
	signedData.Write(lenPrefixed(nil))
	// signer = lenPrefixed(signedData) + lenPrefixed(sigs=empty) + lenPrefixed(pubkey=empty)
	var signer bytes.Buffer
	signer.Write(lenPrefixed(signedData.Bytes()))
	signer.Write(lenPrefixed(nil))
	signer.Write(lenPrefixed(nil))
	// v2Val = lenPrefixed(lenPrefixed(signer))
	v2Val := lenPrefixed(lenPrefixed(signer.Bytes()))

	// pair = uint64(4+len(v2Val)) + uint32(apkSigV2ID) + v2Val
	var pair bytes.Buffer
	_ = binary.Write(&pair, binary.LittleEndian, uint64(4+len(v2Val)))
	_ = binary.Write(&pair, binary.LittleEndian, apkSigV2ID)
	pair.Write(v2Val)

	// Pad to align or just write blockSize = pairs + 24
	blockSize := uint64(pair.Len() + 24)
	var sigBlock bytes.Buffer
	_ = binary.Write(&sigBlock, binary.LittleEndian, blockSize)
	sigBlock.Write(pair.Bytes())
	_ = binary.Write(&sigBlock, binary.LittleEndian, blockSize)
	sigBlock.WriteString(apkSigBlockMagic)

	newCD := uint32(cdOffset) + uint32(sigBlock.Len())
	var out bytes.Buffer
	out.Write(rawZip[:cdOffset])
	out.Write(sigBlock.Bytes())
	cdAndEOCD := append([]byte(nil), rawZip[cdOffset:]...)
	// Patch EOCD cdOffset (last 22 bytes + 16, since comment is empty).
	eocdPos := len(cdAndEOCD) - 22
	binary.LittleEndian.PutUint32(cdAndEOCD[eocdPos+16:eocdPos+20], newCD)
	out.Write(cdAndEOCD)
	return out.Bytes(), nil
}

func lenPrefixed(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.LittleEndian.PutUint32(out[:4], uint32(len(b)))
	copy(out[4:], b)
	return out
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
