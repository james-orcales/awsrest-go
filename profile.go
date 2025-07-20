package awsrest

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

type Profile struct {
	Name        string
	Credentials Credentials
	Config      Config
}

// https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html#envvars-list
func ProfileFromEnv() Profile {
	env := os.Environ()
	p := Profile{Name: "default", Config: ConfigDefault}
	for _, kv := range env {
		if kv[:4] != "AWS_" {
			continue
		}
		kv := strings.SplitN(kv, "=", 2)
		if len(kv) < 2 {
			continue
		}
		k, v := kv[0], kv[1]
		switch k {
		case "AWS_ACCESS_KEY_ID":
			p.Credentials.AccessKeyID = v
		case "AWS_DEFAULT_REGION":
			p.Config.Region = v
		case "AWS_DEFAULT_OUTPUT":
			p.Config.Output = v
		case "AWS_PROFILE":
			p.Name = v
		case "AWS_SECRET_ACCESS_KEY":
			p.Credentials.SecretAccessKey = v
		}
	}
	return p
}

func ProfileIsValid(p Profile) error {
	if p.Name == "" {
		return errors.New("profile name is required")
	}
	if err := CredentialsIsValid(p.Credentials); err != nil {
		return err
	}
	if err := ConfigIsValid(p.Config); err != nil {
		return err
	}
	return nil
}

type Credentials struct {
	AccessKeyID, SecretAccessKey string
}

func CredentialsIsValid(c Credentials) error {
	if len(c.AccessKeyID) != 20 {
		return fmt.Errorf("access key id length must be 20. got: %s", c.AccessKeyID)
	}
	if len(c.SecretAccessKey) != 40 {
		return errors.New("secret access key length must be 40")
	}
	return nil
}

type Config struct {
	// valid values are json, xml, text.
	Output string
	Region string
}

var ConfigDefault Config = Config{
	Output: OutputJSON,
	Region: RegionAsiaPacificSingapore,
}

func ConfigIsValid(c Config) error {
	switch c.Output {
	case OutputJSON, OutputText, OutputXML:
	default:
		return errors.New("invalid response output config. valid values are json, text, xml")
	}
	switch c.Region {
	case RegionUSEastOhio, RegionUSEastNVirginia, RegionUSWestNCalifornia, RegionUSWestOregon,
		RegionAfricaCapeTown, RegionAsiaPacificHongKong, RegionAsiaPacificHyderabad, RegionAsiaPacificJakarta,
		RegionAsiaPacificMalaysia, RegionAsiaPacificMelbourne, RegionAsiaPacificMumbai, RegionAsiaPacificOsaka,
		RegionAsiaPacificSeoul, RegionAsiaPacificSingapore, RegionAsiaPacificSydney, RegionAsiaPacificThailand,
		RegionAsiaPacificTokyo, RegionCanadaCentral, RegionCanadaWestCalgary, RegionEuropeFrankfurt,
		RegionEuropeIreland, RegionEuropeLondon, RegionEuropeMilan, RegionEuropeParis, RegionEuropeSpain,
		RegionEuropeStockholm, RegionEuropeZurich, RegionIsraelTelAviv, RegionMiddleEastBahrain,
		RegionMiddleEastUAE, RegionMexicoCentral, RegionSouthAmericaSaoPaulo, RegionAWSGovCloudUSEast,
		RegionAWSGovCloudUSWest:
	default:
		return errors.New("invalid region")
	}
	return nil
}

const (
	OutputJSON = "json"
	OutputText = "text"
	OutputXML  = "xml"
)

const (
	// United States Regions
	RegionUSEastOhio        = "us-east-2"
	RegionUSEastNVirginia   = "us-east-1"
	RegionUSWestNCalifornia = "us-west-1"
	RegionUSWestOregon      = "us-west-2"

	// Africa Region
	RegionAfricaCapeTown = "af-south-1"

	// Asia Pacific Regions
	RegionAsiaPacificHongKong  = "ap-east-1"
	RegionAsiaPacificHyderabad = "ap-south-2"
	RegionAsiaPacificJakarta   = "ap-southeast-3"
	RegionAsiaPacificMalaysia  = "ap-southeast-5"
	RegionAsiaPacificMelbourne = "ap-southeast-4"
	RegionAsiaPacificMumbai    = "ap-south-1"
	RegionAsiaPacificOsaka     = "ap-northeast-3"
	RegionAsiaPacificSeoul     = "ap-northeast-2"
	RegionAsiaPacificSingapore = "ap-southeast-1"
	RegionAsiaPacificSydney    = "ap-southeast-2"
	RegionAsiaPacificThailand  = "ap-southeast-7"
	RegionAsiaPacificTokyo     = "ap-northeast-1"

	// Canada Regions
	RegionCanadaCentral     = "ca-central-1"
	RegionCanadaWestCalgary = "ca-west-1"

	// Europe Regions
	RegionEuropeFrankfurt = "eu-central-1"
	RegionEuropeIreland   = "eu-west-1"
	RegionEuropeLondon    = "eu-west-2"
	RegionEuropeMilan     = "eu-south-1"
	RegionEuropeParis     = "eu-west-3"
	RegionEuropeSpain     = "eu-south-2"
	RegionEuropeStockholm = "eu-north-1"
	RegionEuropeZurich    = "eu-central-2"

	// Middle East and Israel
	RegionIsraelTelAviv     = "il-central-1"
	RegionMiddleEastBahrain = "me-south-1"
	RegionMiddleEastUAE     = "me-central-1"

	// Mexico Region
	RegionMexicoCentral = "mx-central-1"

	// South America Region
	RegionSouthAmericaSaoPaulo = "sa-east-1"

	// AWS GovCloud Regions
	RegionAWSGovCloudUSEast = "us-gov-east-1"
	RegionAWSGovCloudUSWest = "us-gov-west-1"
)
