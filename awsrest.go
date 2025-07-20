// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html

package awsrest

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	. "github.com/james-orcales/assert.go"
)

type Request struct {
	Profile  Profile
	Method   string
	Host     string
	RawPath  string
	RawQuery string
	Headers  http.Header
	Payload  []byte
}

// NewRequest creates a new AWS request. The endpoint is the host name + path of the service.
func NewRequest(profile Profile, endpoint string, payload []byte) Request {
	AssertNil(ProfileIsValid(profile))
	Assert(endpoint != "")

	parsed, err := url.Parse("https://" + endpoint)
	AssertNil(err)

	req := Request{
		Profile: profile,
		Method:  http.MethodPost,
		Host:    parsed.Host,
		RawPath: parsed.RawPath,
		Headers: http.Header{
			"Accept":       {MIMETypeJSON},
			"Content-Type": {MIMETypeURLEncoded},
			"Host":         {endpoint},
			"X-Amz-Date":   {time.Now().UTC().Format(LayoutISO8601)},
		},
		Payload: []byte(payload),
	}
	return req
}

func SetPayloadAMZJSON(r *Request) {
}

func SetPayloadURLEncoded(r *Request, payload url.Values) {
	r.Headers.Set("Content-Type", MIMETypeURLEncoded)
	r.Payload = []byte(URIEncode(payload))
}

// BuildHTTPRequest builds the HTTP request from the Request struct.
func BuildHTTPRequest(r Request) *http.Request {
	hr, err := http.NewRequest(r.Method, "https://"+r.Host, bytes.NewReader(r.Payload))
	AssertNil(err)
	hr.Header = r.Headers
	return hr
}

// Signs the request by modifying its Headers and adding the Authorization Header.
func Sign(r Request) {
	Assert(len(r.Profile.Credentials.AccessKeyID) == 20)
	Assert(ServiceCode(r.Host) != "")

	credentialScope := "Credential=" + strings.Join(
		[]string{
			r.Profile.Credentials.AccessKeyID,
			Date(r, LayoutYYYYMMDD),
			r.Profile.Config.Region,
			ServiceCode(r.Host),
			"aws4_request",
		},
		"/",
	)

	signedHeaders := "SignedHeaders=" + SignedHeaders(r.Headers)
	signature := "Signature=" + Signature(r)

	// should be comma + space apparently. it's not mentioned in the official docs.
	// i just reverse engineered from the aws cli --debug logs
	header := strings.Join([]string{
		AlgorithmHMACSHA256 + " " + credentialScope,
		signedHeaders,
		signature,
	}, ", ")
	r.Headers.Set("Authorization", header)
}

func Signature(r Request) string {
	r.Headers.Del("Authorization")
	stringToSign := GetStringToSign(r)
	signingKey := DeriveSigningKey(
		r.Profile.Credentials.SecretAccessKey,
		Date(r, LayoutYYYYMMDD),
		r.Profile.Config.Region,
		ServiceCode(r.Host),
	)
	signature := HMACSHA256Hex([]byte(signingKey), []byte(stringToSign))
	return signature
}

func CanonicalRequest(r Request) string {
	canonicalRequest := strings.Join([]string{
		r.Method,
		CanonicalURI(r.RawPath, r.RawQuery),
		CanonicalQueryString(r.RawQuery),
		CanonicalHeadersString(r.Headers),
		SignedHeaders(r.Headers),
		string(SHA256Hex(r.Payload)),
	}, "\n")
	return canonicalRequest
}

// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html#derive-signing-key
func DeriveSigningKey(secret, date, region, service string) string {
	XAssert(func() bool {
		Assert(len(secret) == 40)
		_, err := time.Parse(LayoutYYYYMMDD, date)
		AssertNil(err)
		Assert(region != "")
		Assert(service != "")
		return true
	})

	bdate := []byte(date)
	bregion := []byte(region)
	bservice := []byte(service)

	key := HMACSHA256([]byte("AWS4"+secret), bdate)
	key = HMACSHA256(key, bregion)
	key = HMACSHA256(key, bservice)
	return string(HMACSHA256(key, []byte("aws4_request")))
}

func GetStringToSign(r Request) string {
	credentialScope := strings.Join(
		[]string{
			Date(r, LayoutYYYYMMDD),
			r.Profile.Config.Region,
			ServiceCode(r.Host),
			"aws4_request",
		},
		"/",
	)

	cr := CanonicalRequest(r)
	crDigest := string(SHA256Hex([]byte(cr)))
	ss := strings.Join(
		[]string{AlgorithmHMACSHA256, Date(r, LayoutISO8601), credentialScope, crDigest},
		"\n",
	)
	return ss
}

func CanonicalURI(path, rawquery string) string {
	if path == "" {
		path = "/"
	}
	if rawquery != "" {
		path += "?"
	}
	return path
}

func CanonicalQueryString(rawquery string) string {
	return strings.ReplaceAll(rawquery, "+", "%20")
}

func CanonicalHeadersString(headers http.Header) string {
	clean := make(map[string]string)
	sortedKeys := make([]string, 0, len(headers))
	for key, vals := range headers {
		key = strings.ToLower(key)
		sortedKeys = append(sortedKeys, key)

		valuesClean := make([]string, 0, len(vals))
		for _, v := range vals {
			valuesClean = append(
				valuesClean,
				strings.Join(strings.Fields(strings.Trim(v, " ")), " "),
			)
		}
		clean[key] = strings.Join(valuesClean, ",")
	}
	slices.Sort(sortedKeys)

	sb := strings.Builder{}
	Assert(slices.IsSorted(sortedKeys))
	for _, k := range sortedKeys {
		sb.WriteString(k)
		sb.WriteByte(':')
		sb.WriteString(clean[k])
		sb.WriteByte('\n')
	}
	return sb.String()
}

func SignedHeaders(headers http.Header) string {
	headersClean := make([]string, 0, len(headers))
	for k := range headers {
		headersClean = append(headersClean, strings.ToLower(k))
	}
	slices.Sort(headersClean)
	return strings.Join(headersClean, ";")
}

func SHA256Hex(data []byte) []byte {
	se := sha256.Sum256(data)
	buf := make([]byte, hex.EncodedLen(len(se)))
	hex.Encode(buf, se[:])
	return buf
}

func HMACSHA256Hex(key, data []byte) string {
	return hex.EncodeToString(HMACSHA256(key, data))
}

func HMACSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(data))
	return h.Sum(nil)
}

func URIEncode(data url.Values) string {
	return strings.ReplaceAll(data.Encode(), "+", "%20")
}

// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-troubleshooting.html#signature-v4-troubleshooting-credential-scope
// If the credential scope does not specify the same service as the host header, the signature
// verification step fails
func ServiceCode(host string) string {
	return strings.SplitN(host, ".", 2)[0]
}

// Date looks for the Date in the X-Amz-Date header. Deliberately does not check Date header or
// X-Amz-Date query parameter. Crashes if X-Amz-Date is an invalid ISO 8601 or YYYYMMDD datetime.
func Date(r Request, layout string) string {
	Assert(layout == LayoutISO8601 || layout == LayoutYYYYMMDD)

	dateStr := r.Headers.Get("X-Amz-Date")
	_, err := time.Parse(LayoutISO8601, dateStr)
	AssertNil(err)
	if layout == LayoutYYYYMMDD {
		dateStr = dateStr[:8]
	}
	return dateStr
}

const (
	LayoutISO8601       = "20060102T150405Z"
	LayoutYYYYMMDD      = "20060102"
	Version             = "2015-12-01"
	AlgorithmHMACSHA256 = "AWS4-HMAC-SHA256"
)

const (
	MIMETypeURLEncoded = "application/x-www-form-urlencoded; charset=utf-8"
	MIMETypeAMZJSON    = "application/x-amz-json-1.1"
	MIMETypeJSON       = "application/json"
)
