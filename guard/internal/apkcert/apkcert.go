package apkcert

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
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

	derTagBoolean     = 0x01
	derTagInteger     = 0x02
	derTagBitString   = 0x03
	derTagOctetString = 0x04
	derTagOID         = 0x06
	derTagSequence    = 0x30
	derTagCtx0        = 0xa0
	derTagCtx3        = 0xa3
)

var (
	// 1.2.840.113549.1.7.2 (PKCS#7 SignedData)
	oidPKCS7SignedDataDER = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}
	// 2.5.29.19 (X.509 BasicConstraints)
	oidBasicConstraintsDER = []byte{0x55, 0x1d, 0x13}
)

// readDERTLV reads one canonical DER tag-length-value element without pulling
// encoding/asn1 or math/big into sandbox_guard.
func readDERTLV(data []byte) (tag byte, full, body, rest []byte, err error) {
	if len(data) < 2 {
		return 0, nil, nil, nil, errors.New("truncated DER element")
	}
	tag = data[0]
	if tag&0x1f == 0x1f {
		return 0, nil, nil, nil, errors.New("unsupported high-tag-number DER element")
	}
	l := data[1]
	hdrLen := 2
	var length int
	if l < 0x80 {
		length = int(l)
	} else {
		n := int(l & 0x7f)
		if n == 0 || l == 0xff || n > 4 {
			return 0, nil, nil, nil, errors.New("invalid DER length encoding")
		}
		if len(data) < 2+n {
			return 0, nil, nil, nil, errors.New("truncated DER multi-byte length")
		}
		if data[2] == 0 {
			return 0, nil, nil, nil, errors.New("non-canonical DER length")
		}
		for i := 0; i < n; i++ {
			length = (length << 8) | int(data[2+i])
		}
		if length < 0x80 {
			return 0, nil, nil, nil, errors.New("non-canonical short DER length")
		}
		hdrLen += n
	}
	if len(data)-hdrLen < length {
		return 0, nil, nil, nil, errors.New("truncated DER value")
	}
	end := hdrLen + length
	return tag, data[:end], data[hdrLen:end], data[end:], nil
}

// validateX509CertDER verifies X.509 DER structure using strict DER TLV scanning
// without pulling encoding/asn1, crypto/x509, or math/big into sandbox_guard.
func validateX509CertDER(der []byte) (bool, error) {
	if len(der) == 0 {
		return false, errors.New("empty certificate DER")
	}
	outerTag, _, certBody, rest, err := readDERTLV(der)
	if err != nil {
		return false, err
	}
	if outerTag != derTagSequence {
		return false, errors.New("malformed X.509 outer sequence")
	}
	if len(rest) != 0 {
		return false, errors.New("trailing data after X.509 certificate")
	}

	tbsTag, _, tbsBody, r, err := readDERTLV(certBody)
	if err != nil || tbsTag != derTagSequence {
		return false, errors.New("malformed X.509 outer sequence")
	}
	sigAlgTag, _, _, r, err := readDERTLV(r)
	if err != nil || sigAlgTag != derTagSequence {
		return false, errors.New("malformed X.509 outer sequence")
	}
	sigValTag, _, sigValBody, r, err := readDERTLV(r)
	if err != nil || sigValTag != derTagBitString || len(sigValBody) == 0 || len(r) != 0 {
		return false, errors.New("malformed X.509 outer sequence")
	}

	cur := tbsBody
	tag, _, body, next, err := readDERTLV(cur)
	if err != nil {
		return false, err
	}
	if tag == derTagCtx0 {
		vTag, _, vBody, vRest, vErr := readDERTLV(body)
		if vErr != nil || vTag != derTagInteger || len(vBody) == 0 || len(vRest) != 0 {
			return false, errors.New("invalid X.509 version")
		}
		tag, _, body, next, err = readDERTLV(next)
		if err != nil {
			return false, err
		}
	}
	if tag != derTagInteger || len(body) == 0 {
		return false, errors.New("invalid X.509 serialNumber")
	}
	cur = next

	for i := 0; i < 5; i++ {
		fTag, _, _, fNext, fErr := readDERTLV(cur)
		if fErr != nil || fTag != derTagSequence {
			return false, errors.New("malformed X.509 TBSCertificate fields")
		}
		cur = fNext
	}

	if len(cur) > 0 && cur[0] == 0x81 {
		if _, _, _, cur, err = readDERTLV(cur); err != nil {
			return false, err
		}
	}
	if len(cur) > 0 && cur[0] == 0x82 {
		if _, _, _, cur, err = readDERTLV(cur); err != nil {
			return false, err
		}
	}
	if len(cur) == 0 || cur[0] != derTagCtx3 {
		return false, nil
	}
	_, _, extsWrapper, _, err := readDERTLV(cur)
	if err != nil {
		return false, err
	}
	seqTag, _, extsBody, extsRest, err := readDERTLV(extsWrapper)
	if err != nil || seqTag != derTagSequence || len(extsRest) != 0 {
		return false, errors.New("malformed X.509 extensions")
	}
	for len(extsBody) > 0 {
		extTag, _, extBody, extNext, extErr := readDERTLV(extsBody)
		if extErr != nil || extTag != derTagSequence {
			return false, errors.New("malformed X.509 extension")
		}
		extsBody = extNext

		oidTag, _, oidBytes, eRest, eErr := readDERTLV(extBody)
		if eErr != nil || oidTag != derTagOID {
			return false, errors.New("malformed X.509 extension OID")
		}
		if len(eRest) > 0 && eRest[0] == derTagBoolean {
			if _, _, critBody, nextRest, cErr := readDERTLV(eRest); cErr != nil || len(critBody) != 1 {
				return false, errors.New("malformed X.509 extension critical flag")
			} else {
				eRest = nextRest
			}
		}
		valTag, _, valBytes, valRest, vErr := readDERTLV(eRest)
		if vErr != nil || valTag != derTagOctetString || len(valRest) != 0 {
			return false, errors.New("malformed X.509 extension value")
		}
		if !bytes.Equal(oidBytes, oidBasicConstraintsDER) {
			continue
		}
		bcTag, _, bcBody, _, bcErr := readDERTLV(valBytes)
		if bcErr == nil && bcTag == derTagSequence && len(bcBody) > 0 && bcBody[0] == derTagBoolean {
			if _, _, caBody, _, caErr := readDERTLV(bcBody); caErr == nil && len(caBody) == 1 && caBody[0] != 0 {
				return true, nil
			}
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
	ciTag, _, ciBody, _, err := readDERTLV(der)
	if err != nil || ciTag != derTagSequence {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("malformed PKCS7 ContentInfo")
	}
	ctTag, _, ctOID, ciRest, err := readDERTLV(ciBody)
	if err != nil || ctTag != derTagOID {
		return nil, errors.New("malformed PKCS7 ContentType")
	}
	if !bytes.Equal(ctOID, oidPKCS7SignedDataDER) {
		return nil, errors.New("not PKCS7 SignedData")
	}
	contentTag, _, contentBody, _, err := readDERTLV(ciRest)
	if err != nil || contentTag != derTagCtx0 {
		return nil, errors.New("missing PKCS7 SignedData content")
	}
	sdTag, _, sdBody, _, err := readDERTLV(contentBody)
	if err != nil || sdTag != derTagSequence {
		return nil, errors.New("malformed PKCS7 SignedData sequence")
	}
	verTag, _, _, r, err := readDERTLV(sdBody)
	if err != nil || verTag != derTagInteger {
		return nil, errors.New("malformed PKCS7 SignedData version")
	}
	// Skip DigestAlgorithms and EncapContentInfo.
	if _, _, _, r, err = readDERTLV(r); err != nil {
		return nil, err
	}
	if _, _, _, r, err = readDERTLV(r); err != nil {
		return nil, err
	}
	var certsBytes []byte
	if len(r) > 0 && r[0] == derTagCtx0 {
		_, _, certsBytes, _, err = readDERTLV(r)
		if err != nil {
			return nil, err
		}
	}
	var leafHashes, allHashes []string
	rest := certsBytes
	for len(rest) > 0 {
		var certFull []byte
		_, certFull, _, rest, err = readDERTLV(rest)
		if err != nil {
			return nil, err
		}
		isCA, err := validateX509CertDER(certFull)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(certFull)
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
