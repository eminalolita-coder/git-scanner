package main

import (
	"encoding/xml"
	"fmt"
)

const body = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::1:user/x</Arn>
    <UserId>UID</UserId>
    <Account>123</Account>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>`

func main() {
	// variante A : structure actuelle (imbricee avec tags)
	var a struct {
		GetCallerIdentityResponse struct {
			Result struct {
				Account string `xml:"Account"`
				ARN     string `xml:"Arn"`
				UserID  string `xml:"UserId"`
			} `xml:"GetCallerIdentityResult"`
		} `xml:"GetCallerIdentityResponse"`
	}
	fmt.Println("A err:", xml.Unmarshal([]byte(body), &a), "arn=", a.GetCallerIdentityResponse.Result.ARN)

	// variante B : plat avec chemins
	var b struct {
		ARN     string `xml:"GetCallerIdentityResult>Arn"`
		Account string `xml:"GetCallerIdentityResult>Account"`
	}
	fmt.Println("B err:", xml.Unmarshal([]byte(body), &b), "arn=", b.ARN)

	// variante C : niveaux nommes
	type result struct {
		ARN     string `xml:"Arn"`
		Account string `xml:"Account"`
	}
	type resp struct {
		Result result `xml:"GetCallerIdentityResult"`
	}
	var c struct {
		R resp `xml:"GetCallerIdentityResponse"`
	}
	fmt.Println("C err:", xml.Unmarshal([]byte(body), &c), "arn=", c.R.Result.ARN)

	// dump complet de A
	fmt.Printf("A=%+v\n", a)
}
