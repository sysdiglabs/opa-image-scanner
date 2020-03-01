package imageadmission

allow_image {
	input.message == "hello"
}

allow_image {
	input.ScanReport.Status == "pass"
}

deny_image[msg] {
	not allow_image
	msg := "Denying images by default"
}

deny_image[msg] {
	not allow_image
	msg := "Because I want to deny"
}

deny_image[msg] {
	not allow_image
	msg := input.ScanReport.Status
}