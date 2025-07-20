package awsrest_test

import (
	"net/url"
	"testing"
)

var profile = Profile{
	Name: "default",
	Credentials: Credentials{
		AccessKeyID:     "MY_CUSTOM_ACCESS_KEY",
		SecretAccessKey: "MY_SECRET_ACCESS_KEYMY_SECRET_ACCESS_KEY",
	},
	Config: Config{Region: RegionAsiaPacificMalaysia, Output: "json"},
}

func TestHMACSHA256(t *testing.T) {
	actual := HMACSHA256Hex([]byte("foobarbaz"), []byte("bazbarfoo"))
	expected := `3b10a1be09a87fc76c64826f2d770fc9f589835865971bd418de2cb00efc88e4`
	if actual != expected {
		t.Fatalf("HMACSHA256 hash is wrong. got: \n%s\nexpected: \n%s", actual, expected)
	}
}

func TestSignature(t *testing.T) {
	r := NewSignedRequest(
		profile,
		"elasticloadbalancing.ap-southeast-1.amazonaws.com",
		url.Values{
			"Action":         {"DescribeLoadBalancers"},
			"Names.member.1": {"my-application-load-balancer"},
		},
	)
	r.Headers.Set("X-Amz-Date", LayoutISO8601)
	actual := Signature(r)
	expected := `3e1aa462473629761f9a9b00f828f0b53a68b95187af4c164a48680b34040a0f`
	if actual != expected {
		t.Fatalf("signature is wrong. \ngot: \n%s\nexpected: \n%s", actual, expected)
	}
}
