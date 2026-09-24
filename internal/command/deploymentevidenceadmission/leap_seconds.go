package deploymentevidenceadmission

import (
	"slices"
	"time"
)

// Historical UTC insertion dates from the IERS list distributed by IANA.
// https://data.iana.org/time-zones/tzdb/leap-seconds.list
var positiveLeapDays = []string{
	"1972-06-30", "1972-12-31", "1973-12-31", "1974-12-31",
	"1975-12-31", "1976-12-31", "1977-12-31", "1978-12-31",
	"1979-12-31", "1981-06-30", "1982-06-30", "1983-06-30",
	"1985-06-30", "1987-12-31", "1989-12-31", "1990-12-31",
	"1992-06-30", "1993-06-30", "1994-06-30", "1995-12-31",
	"1997-06-30", "1998-12-31", "2005-12-31", "2008-12-31",
	"2012-06-30", "2015-06-30", "2016-12-31",
}

func validRFC3339UTC(value string) bool {
	if !rfc3339UTCRegexp.MatchString(value) {
		return false
	}
	if value[17:19] != "60" {
		_, err := time.Parse(time.RFC3339Nano, value)
		return err == nil
	}
	if value[11:16] != "23:59" || !slices.Contains(positiveLeapDays, value[:10]) {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, value[:17]+"59"+value[19:])
	return err == nil
}
