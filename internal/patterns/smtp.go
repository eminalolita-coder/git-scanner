package patterns

import "regexp"

// reSMTPHost matches an SMTP provider host, reused for context pairing.
var reSMTPHost = regexp.MustCompile(`(?i)\b((?:smtp|smtp-relay|smtp25|mail|email|secure|pro|in-v3)[a-z0-9.-]*\.(?:sendgrid\.net|mailgun\.org|sendinblue\.com|brevo\.com|mailjet\.com|tipimail\.com|sparkpostmail\.com|deliverabilitymanager\.net|mailendo\.com|smtpeter\.com|smtp2go\.com|socketlabs\.com|emailsrvr\.com|infomaniak\.com|pepipost\.com|elasticemail\.com|turbo-smtp\.com|smtp-pulse\.com|mandrillapp\.com|postmarkapp\.com|mailchimp\.com|sendpulse\.com|moosend\.com|mailerlite\.com|zoho\.com|office365\.com|outlook\.com|gmail\.com|googlemail\.com|amazonaws\.com),?)(?::(25|2525|465|587|443))?\b`)

// FirstSMTPHost returns the first SMTP provider host in content, and its port
// when written next to it. This is the context that gives credentials their
// meaning, the same way a `grep -C25` on SMTP hosts does.
func FirstSMTPHost(content []byte) (host, port string) {
	m := reSMTPHost.FindSubmatch(content)
	if m == nil {
		return "", ""
	}
	host = string(m[1])
	if len(m) > 2 && len(m[2]) > 0 {
		port = string(m[2])
	}
	return host, port
}
