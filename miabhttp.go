package miabhttp

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"

	"github.com/asaskevich/govalidator"
	country "github.com/mikekonan/go-countries"
)

type Context struct {
	cServer   string // e.g. "box.example.com"
	cAPIPath  string // Optional, defaults to "admin" during CreateMiabContext() if left as empty str. If you don't want any path, use "/" (since an empty string defaults to "admin"). Using "/" is the only case where you should include the slash in this variable. The context resulting from CreateMiabContext() will never have an empty string, since it will always be "/", "admin", or something else.
	cUsername string // Full e-mail, or whatever you normally use to login
	cPassword string // This or APIToken must be provided
	cAPIToken string // This or password must be provided
	cOTPcode  string // string of 6-digit 2FA code if needed. NOT THE SECRET. IF YOU NEED A LONG SESSION, USE YOUR 2FA CODE TO LoginAndReturnAPIKey() AND GET AN API token FOR AN INSTANCE OF THIS STRUCT WITHOUT A PASSWORD. DON'T FORGET TO Logout().
}

type MiabError struct {
	IsHTTPStatusError bool
	HTTPStatusCode    int
	CallingFunction   string
	ErrorMsg          string
}

func (m MiabError) Error() string {
	return m.ErrorMsg
}

func (m MiabError) String() string {
	return fmt.Sprintf("MiabError{\n  IsHTTPStatusError: %t,\n  "+
		"HTTPStatusCode:    %d,\n  "+
		"CallingFunction:   \"%s\",\n  "+
		"ErrorMsg:          \"%s\",\n}",
		m.IsHTTPStatusError, m.HTTPStatusCode, m.CallingFunction, m.ErrorMsg)
}

// See Context struct comments for notes on parameter requirements
func CreateMiabContext(server, apipath, username, password, apitoken, otpcode string) (*Context, error) {
	if !govalidator.IsDNSName(server) {
		return nil, MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "CreateMiabContext",
			ErrorMsg:          "invalid server DNS name",
		}
	}
	if username == "" {
		return nil, MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "CreateMiabContext",
			ErrorMsg:          "username must not be empty",
		}
	}
	if password == "" && apitoken == "" {
		return nil, MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "CreateMiabContext",
			ErrorMsg:          "password and API token cannot both be empty",
		}
	}

	if apipath == "" {
		apipath = "admin"
	}
	return &Context{
		cServer:   server,
		cAPIPath:  apipath,
		cUsername: username,
		cPassword: password,
		cAPIToken: apitoken,
		cOTPcode:  otpcode,
	}, nil
}

func (c *Context) Server() string {
	var valuecopy string = c.cServer
	return valuecopy
}

func (c *Context) APIPath() string {
	var valuecopy string = c.cAPIPath
	return valuecopy
}

func (c *Context) Username() string {
	var valuecopy string = c.cUsername
	return valuecopy
}

func (c *Context) Password() string {
	var valuecopy string = c.cPassword
	return valuecopy
}

func (c *Context) APIToken() string {
	var valuecopy string = c.cAPIToken
	return valuecopy
}

func (c *Context) OTPcode() string {
	var valuecopy string = c.cOTPcode
	return valuecopy
}

func (c *Context) InsertAPITokenAndDeletePassword(apitoken string) error {
	if apitoken == "" {
		return MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "InsertAPITokenAndDeletePassword",
			ErrorMsg:          "input API token cannot be blank",
		}
	}
	c.cPassword = ""
	c.cOTPcode = ""
	c.cAPIToken = apitoken
	return nil
}

type methodType string
type requestContentType string
type responseContentType string

const (
	// Allowed HTTP methods
	mGET    methodType = "GET"
	mPOST   methodType = "POST"
	mPUT    methodType = "PUT"
	mDELETE methodType = "DELETE"

	// Allowed request content types
	ctTextPlain requestContentType = "text/plain"
	ctFormData  requestContentType = "application/x-www-form-urlencoded"

	// Non-erroring response content types
	crTextHtml  responseContentType = "text/html"
	crTextPlain responseContentType = "text/plain"
	ctJson      responseContentType = "application/json"
)

func checkStatusCode(statuscode int, fn string) error {
	x := MiabError{}
	x.IsHTTPStatusError = true
	x.HTTPStatusCode = statuscode
	x.CallingFunction = fn
	if statuscode == 400 {
		x.ErrorMsg = "400 Bad Request"
	} else if statuscode == 401 {
		x.ErrorMsg = "401 Unauthorized"
	} else if statuscode == 403 {
		x.ErrorMsg = "403 Forbidden"
	} else if statuscode == 500 {
		x.ErrorMsg = "500 Internal Server Error"
	} else if statuscode != 200 {
		// This message is most likely to be part of a panic, so it is more detailed
		x.ErrorMsg = "miabhttp." + fn + "(): Server sent unexpected status code response"
	}
	// We exclude 404 Not Found, since we control the path. A 404 means the
	// upstream API has changed, so the non-200 fallback error message is more
	// useful anyway.
	if statuscode == 200 {
		return nil
	}
	return x
}

// HTTP request wrapper func to allow me to include a text or
// map[string]interface{} body type, while also sanity checking some basic
// parameters
func (c *Context) makeRequest(method methodType, ct requestContentType, url string, body interface{}, prefer_apitoken bool) (*http.Request, error) {
	var req *http.Request
	if body != nil {
		if ct == ctFormData {
			vb := body.(map[interface{}]interface{})
			nb := neturl.Values{}
			for k, v := range vb {
				nb.Add(k.(string), v.(string))
			}
			req, _ = http.NewRequest(string(method), url, strings.NewReader(nb.Encode()))
			if method == mPOST {
				req.Header.Set("content-type", string(ctFormData))
			}
		} else {
			b, _ := body.(string)
			req, _ = http.NewRequest(string(method), url, bytes.NewBuffer([]byte(b)))
			req.Header.Set("content-type", string(ctTextPlain))
		}
	} else {
		req, _ = http.NewRequest(string(method), url, nil)
		req.Header.Set("content-type", string(ctFormData))
	}

	if prefer_apitoken {
		if c.cAPIToken != "" {
			req.SetBasicAuth(c.Username(), c.APIToken())
		} else {
			req.SetBasicAuth(c.Username(), c.Password())
			if c.cOTPcode != "" {
				req.Header.Add("x-auth-token", c.OTPcode())
			}
		}
	} else {
		if c.cPassword != "" {
			req.SetBasicAuth(c.Username(), c.Password())
			if c.cOTPcode != "" {
				req.Header.Add("x-auth-token", c.OTPcode())
			}
		} else {
			req.SetBasicAuth(c.Username(), c.APIToken())
		}
	}
	return req, nil
}

func (c *Context) makeUrl(usetls bool) string {
	url := "http"
	if usetls {
		url = url + "s"
	}
	url = url + "://"
	url = url + c.cServer
	if c.cAPIPath != "/" {
		url = url + "/" + c.cAPIPath
	}
	return url
}

// HTTP client request/response wrapper specifically for the way this library
// works. It was made once I realized how often I was doing this, so I made this
// function as a generic for all possible library uses. Therefore, it is dumb
// and complicated, but it does what it needs to do.
func (c *Context) doTheThing(method methodType, urlpostfix string, ct requestContentType, input interface{}, callername string, jsonbool bool) (int, responseContentType, interface{}, error, error) {
	switch method {
	case mGET, mPOST, mPUT, mDELETE:
		break
	default:
		return 0, ctJson, []byte{}, nil, MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "doTheThing",
			ErrorMsg:          "invalid HTTP method",
		}
	}

	switch ct {
	case ctTextPlain, ctFormData:
		break
	default:
		return 0, ctJson, []byte{}, nil, MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "doTheThing",
			ErrorMsg:          "invalid HTTP content-type for request",
		}
	}

	var req *http.Request
	var resp *http.Response
	var err error

	client := &http.Client{}
	if ct == ctTextPlain {
		in, _ := input.(string)
		if len(in) == 0 {
			req, err = c.makeRequest(method, ct, c.makeUrl(true)+urlpostfix, nil, urlpostfix != "/login")
		} else {
			req, err = c.makeRequest(method, ct, c.makeUrl(true)+urlpostfix, in, urlpostfix != "/login")
		}
	} else if ct == ctFormData {
		in, _ := input.(map[interface{}]interface{})
		req, err = c.makeRequest(method, ct, c.makeUrl(true)+urlpostfix, in, urlpostfix != "/login")
	} // else { should not get here }
	if err != nil {
		return 0, ctJson, []byte{}, nil, err
	}
	resp, err = client.Do(req)
	if err != nil {
		return 0, ctJson, []byte{}, nil, err
	}
	defer resp.Body.Close()

	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, ctJson, []byte{}, nil, err
	}
	var ctr responseContentType
	var rb interface{}
	rct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(rct, string(crTextHtml)) {
		ctr = crTextHtml
		rb = string(body)
	} else if strings.Contains(rct, string(crTextPlain)) {
		ctr = crTextPlain
		rb = string(body)
	} else if strings.Contains(rct, string(ctJson)) {
		ctr = ctJson
		if jsonbool {
			rb = string(body)
		} else {
			rb = map[interface{}]interface{}{}
			json.Unmarshal([]byte(body), &rb)
		}
	} else {
		return 0, ctJson, []byte{}, nil, MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "doTheThing",
			ErrorMsg:          "MIAB API has returned an unknown response content type",
		}
	}

	statuserr := checkStatusCode(resp.StatusCode, callername)

	return resp.StatusCode, ctr, rb, statuserr, nil
}

// https://mailinabox.email/api-docs.html#operation/login
// Return value is usually a map[string]interface{}, but may be string on
// non-200 status codes that return strings.
func (c *Context) Login() (interface{}, error) {

	_, _, b, serr, err := c.doTheThing("POST", "/login", "text/plain", nil, "Login", false)

	if err != nil {
		return nil, err
	} else if serr != nil {
		return string(b.(string)), serr
	}

	return b.(map[string]interface{}), nil
}

// This performs a login without using a context, in order to keep the password
// scope inside this function, so it will be GC'd ASAP.
// If the return err is nil, the string returned will be the apikey or an empty
// string if the login credentials were invalid.
// All other scenarios should return an error.
// Much of the code is copied from doTheThing() and makeUrl().
// This is the only exportable function in this library that does not need the
// Context struct.
func LoginAndReturnAPIKey(server, apipath, username, password, otpcode string, https bool) (string, error) {
	if !govalidator.IsDNSName(server) {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "LoginAndReturnAPIKey",
			ErrorMsg:          "server parameter is invalid",
		}
	}
	if apipath == "" {
		apipath = "admin"
	}
	urlpath := "http"
	if https {
		urlpath = urlpath + "s"
	}
	urlpath = urlpath + "://"
	urlpath = urlpath + server
	if apipath != "/" {
		urlpath = urlpath + "/" + apipath
	}
	urlpath = urlpath + "/login"
	var req *http.Request
	client := &http.Client{}
	req, _ = http.NewRequest("POST", urlpath, nil)
	req.Header.Set("content-type", string(ctTextPlain))
	req.SetBasicAuth(username, password)
	if otpcode != "" {
		req.Header.Add("x-auth-token", otpcode)
	}
	var resp *http.Response
	var err error
	resp, err = client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var body []byte
	body, _ = ioutil.ReadAll(resp.Body)
	statuserr := checkStatusCode(resp.StatusCode, "LoginAndReturnAPIKey")
	if statuserr != nil {
		return string(body), statuserr
	}
	var rb interface{}
	isstring := true
	rct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(rct, string(crTextHtml)) {
		rb = string(body)
	} else if strings.Contains(rct, string(crTextPlain)) {
		rb = string(body)
	} else if strings.Contains(rct, string(ctJson)) {
		isstring = false
		rb = map[interface{}]interface{}{}
		json.Unmarshal([]byte(body), &rb)
	} else {
		return string(body), MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "LoginAndReturnAPIKey",
			ErrorMsg:          "Response content type unknown",
		}
	}
	if isstring {
		return rb.(string), MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "LoginAndReturnAPIKey",
			ErrorMsg:          "Response returned unexpected data",
		}
	}

	rrb := rb.(map[string]interface{})

	if rrb["status"].(string) == "ok" {
		return rrb["api_key"].(string), nil
	} else if rrb["status"].(string) == "invalid" {
		return "", nil
	}

	return "", MiabError{
		IsHTTPStatusError: false,
		CallingFunction:   "LoginAndReturnAPIKey",
		ErrorMsg:          "upstream API has changed and this function has reached an unexpected area",
	}
}

// https://mailinabox.email/api-docs.html#operation/logout
// Return value is usually a map[string]interface{}, but may be string on
// non-200 status codes that return strings.
func (c *Context) Logout() (interface{}, error) {

	_, _, b, serr, err := c.doTheThing("POST", "/logout", "text/plain", nil, "Logout", false)
	if err != nil {
		return map[string]interface{}{}, err
	} else if serr != nil {
		return string(b.(string)), serr
	}

	return b.(map[string]interface{}), nil
}

// https://mailinabox.email/api-docs.html#operation/getMailUsers
// The returned interface{} will be type string or []map[string]interface{}
// depending on which format you choose.
// However, if you choose json and and a non-200 status is returned, the return
// will still be string, so you must check if error is nil.
// The return value will only be a []map[string]interface{} if format is json
// and response status code is 200.
// This is done to keep in line with how the MIAB HTTP API actually works.
func (c *Context) GetMailUsers(format string) (interface{}, error) {
	switch format {
	case "text", "json":
		break
	default:
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "GetMailUsers",
			ErrorMsg:          "invalid format parameter",
		}
	}

	_, _, b, serr, err := c.doTheThing("GET", "/mail/users?format="+format, "text/plain", nil, "GetMailUsers", false)
	if err != nil {
		return "", err
	} else if serr != nil {
		return string(b.(string)), serr
	}

	if format == "text" {
		return string(b.(string)), nil
	}

	b2 := b.([]interface{})
	ret := []map[string]interface{}{}
	for _, mapstringinterface := range b2 {
		ret = append(ret, mapstringinterface.(map[string]interface{}))
	}

	return ret, nil
}

// https://mailinabox.email/api-docs.html#operation/addMailUser
func (c *Context) AddMailUser(email, password, privileges string) (string, error) {
	if privileges != "" && privileges != "admin" {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "AddMailUser",
			ErrorMsg:          "privileges parameter must be \"admin\" or empty string",
		}
	}

	body := make(map[interface{}]interface{})
	body["email"] = email
	body["password"] = password
	body["privileges"] = privileges

	_, _, b, serr, err := c.doTheThing("POST", "/mail/users/add", "application/x-www-form-urlencoded", body, "AddMailUser", false)
	if err != nil {
		return "", err
	}

	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/removeMailUser
func (c *Context) RemoveMailUser(email string) (string, error) {
	body := make(map[interface{}]interface{})
	body["email"] = email

	_, _, b, serr, err := c.doTheThing("POST", "/mail/users/remove", "application/x-www-form-urlencoded", body, "RemoveMailUser", false)
	if err != nil {
		return "", err
	}

	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/addMailUserPrivilege
// Note that although the docs say the privilege param can be admin or empty
// str, it will return a 400 bad request if you try to remove the privilege "",
// so for now, I ignore the input param and always set admin. Even so, the
// function signature is left as is since that's what the upstream docs have.
func (c *Context) AddMailUserPrivilege(email, privilege string) (string, error) {
	if privilege != "" && privilege != "admin" {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "AddMailUserPrivilege",
			ErrorMsg:          "privilege parameter must be \"admin\" or empty string",
		}
	}

	body := make(map[interface{}]interface{})
	body["email"] = email

	// May be set to more than "admin" at some point in the future
	//body["privilege"] = privilege
	body["privilege"] = "admin"

	_, _, b, serr, err := c.doTheThing("POST", "/mail/users/privileges/add", "application/x-www-form-urlencoded", body, "AddMailUserPrivilege", false)
	if err != nil {
		return "", err
	}

	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/removeMailUserPrivilege
// Note that although the docs say the privilege param can be admin or empty
// str, it will return a 400 bad request if you try to remove the privilege "",
// so for now, I ignore the input param and always set admin. Even so, the
// function signature is left as is since that's what the upstream docs have.
func (c *Context) RemoveMailUserPrivilege(email, privilege string) (string, error) {
	if privilege != "" && privilege != "admin" {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "RemoveMailUserPrivilege",
			ErrorMsg:          "privilege parameter must be \"admin\" or empty string",
		}
	}

	body := make(map[interface{}]interface{})
	body["email"] = email

	// May be set to more than "admin" at some point in the future
	//body["privilege"] = privilege
	body["privilege"] = "admin"

	_, _, b, serr, err := c.doTheThing("POST", "/mail/users/privileges/remove", "application/x-www-form-urlencoded", body, "RemoveMailUserPrivilege", false)
	if err != nil {
		return "", err
	}

	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/setMailUserPassword
// Returns 400 bad request err if (among other possibilities) the user
// doesn't exist
func (c *Context) SetMailUserPassword(email, password string) (string, error) {
	body := make(map[interface{}]interface{})
	body["email"] = email
	body["password"] = password

	_, _, b, serr, err := c.doTheThing("POST", "/mail/users/password", "application/x-www-form-urlencoded", body, "SetMailUserPassword", false)
	if err != nil {
		return "", err
	}

	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/getMailUserPrivileges
// Returns empty str with no err if user is not admin;
// returns 400 bad request err if (among other possibilities) the user
// doesn't exist
func (c *Context) GetMailUserPrivileges(email string) (string, error) {
	_, _, b, serr, err := c.doTheThing("GET", "/mail/users/privileges?email="+neturl.QueryEscape(email), "text/plain", nil, "GetMailUserPrivileges", false)
	if err != nil {
		return "", err
	}

	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/getMailDomains
func (c *Context) GetMailDomains() (string, error) {
	_, _, b, serr, err := c.doTheThing("GET", "/mail/domains", "text/plain", nil, "GetMailDomains", false)
	if err != nil {
		return "", err
	}

	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/getMailAliases
// See comments for GetMailUsers() function for information about return types.
// It works the same here.
func (c *Context) GetMailAliases(format string) (interface{}, error) {
	if format != "text" && format != "json" {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "GetMailAliases",
			ErrorMsg:          "format parameter must be \"text\" or \"json\"",
		}
	}
	_, _, b, serr, err := c.doTheThing("GET", "/mail/aliases?format="+format, "text/plain", nil, "GetMailAliases", false)
	if err != nil {
		return "", err
	} else if serr != nil {
		return string(b.(string)), serr
	}

	if format == "text" {
		return string(b.(string)), nil
	}

	b2 := b.([]interface{})
	ret := []map[string]interface{}{}
	for _, mapstringinterface := range b2 {
		ret = append(ret, mapstringinterface.(map[string]interface{}))
	}

	return ret, nil
}

// https://mailinabox.email/api-docs.html#operation/upsertMailAlias
func (c *Context) UpsertMailAlias(update_if_exists int, address, forwards_to string, permitted_senders interface{}) (string, error) {
	if update_if_exists != 0 && update_if_exists != 1 {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "UpsertMailAlias",
			ErrorMsg:          "update_if_exists parameter must be 0 or 1",
		}
	}

	body := make(map[interface{}]interface{})
	body["update_if_exists"] = strconv.Itoa(update_if_exists)
	body["address"] = address
	body["forwards_to"] = forwards_to
	if permitted_senders == nil {
		body["permitted_senders"] = ""
	} else {
		body["permitted_senders"] = permitted_senders.(string)
	}

	_, _, b, serr, err := c.doTheThing("POST", "/mail/aliases/add", "application/x-www-form-urlencoded", body, "UpsertMailAlias", false)
	if err != nil {
		return "", err
	}

	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/removeMailAlias
func (c *Context) RemoveMailAlias(address string) (string, error) {
	body := make(map[interface{}]interface{})
	body["address"] = address

	_, _, b, serr, err := c.doTheThing("POST", "/mail/aliases/remove", "application/x-www-form-urlencoded", body, "RemoveMailAlias", false)
	if err != nil {
		return "", err
	}

	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/getDnsSecondaryNameserver
// Will return a string when there is an error, but if err == nil, then the
// return will be a map[string][]string
func (c *Context) GetDnsSecondaryNameserver() (interface{}, error) {
	_, _, b, serr, err := c.doTheThing("GET", "/dns/secondary-nameserver", "text/plain", nil, "GetDnsSecondaryNameserver", false)
	if err != nil {
		return "", err
	} else if serr != nil {
		return string(b.(string)), serr
	}

	rb := b.(map[string]interface{})
	ret := make(map[string][]string)
	for k, v := range rb {
		vd := v.([]interface{})
		value := []string{}
		for _, v2 := range vd {
			value = append(value, v2.(string))
		}
		ret[k] = value
	}

	return ret, nil
}

// https://mailinabox.email/api-docs.html#operation/addDnsSecondaryNameserver
func (c *Context) AddDnsSecondaryNameserver(hostnames string) (string, error) {
	body := make(map[interface{}]interface{})
	body["hostnames"] = hostnames

	_, _, b, serr, err := c.doTheThing("POST", "/dns/secondary-nameserver", "application/x-www-form-urlencoded", body, "AddDnsSecondaryNameserver", false)
	if err != nil {
		return "", err
	}

	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/getDnsZones
// returns a slice of strings if err != nil, otherwise return value is a string
func (c *Context) GetDnsZones() (interface{}, error) {
	_, _, b, serr, err := c.doTheThing("GET", "/dns/zones", "text/plain", nil, "GetDnsZones", false)
	if err != nil {
		return "", err
	} else if serr != nil {
		return string(b.(string)), serr
	}

	b2 := b.([]interface{})
	ret := []string{}
	for _, v := range b2 {
		ret = append(ret, v.(string))
	}

	return ret, nil
}

// https://mailinabox.email/api-docs.html#operation/getDnsZonefile
func (c *Context) GetDnsZonefile(zone string) (string, error) {
	if !govalidator.IsDNSName(zone) {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "GetDnsZonefile",
			ErrorMsg:          "zone parameter is invalid",
		}
	}
	_, _, b, serr, err := c.doTheThing("GET", "/dns/zonefile/"+neturl.QueryEscape(zone), "text/plain", nil, "GetDnsZonefile", false)
	if err != nil {
		return "", err
	}

	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/updateDns
func (c *Context) UpdateDns(force int) (string, error) {
	if force != 0 && force != 1 {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "UpdateDns",
			ErrorMsg:          "force parameter must be 0 or 1",
		}
	}

	body := make(map[interface{}]interface{})
	body["force"] = strconv.Itoa(force)

	_, _, b, serr, err := c.doTheThing("POST", "/dns/update", "application/x-www-form-urlencoded", body, "UpdateDns", false)
	if err != nil {
		return "", err
	}

	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/getDnsCustomRecords
// returns []map[string]interface{} if err == nil, otherwise returns string
//
// Example slice item of map[string]interface{} with all values:
//	{
//		"qname": "box.example.com",
//		"rtype": "A",
//		"sort-order": {
//			"created": 0,
//			"qname": 0
//		},
//		"value": "1.2.3.4",
//		"zone": "example.com"
//	}
// The interface{} value of the map is a string for everything but sort-order,
// which is a map[string]int
func (c *Context) GetDnsCustomRecords() (interface{}, error) {
	_, _, b, serr, err := c.doTheThing("GET", "/dns/custom", "text/plain", nil, "GetDnsCustomRecords", false)
	if err != nil {
		return "", err
	} else if serr != nil {
		return string(b.(string)), serr
	}

	ret := []map[string]interface{}{}

	b2 := b.([]interface{})

	for _, v := range b2 {
		val := map[string]interface{}{}
		vv := v.(map[string]interface{})
		for k2, v2 := range vv {
			if k2 != "sort-order" {
				val[k2] = v2.(string)
			} else {
				vret := map[string]int{}
				vv2 := v2.(map[string]interface{})
				for k3, v3 := range vv2 {
					vret[k3] = int(math.Round(v3.(float64)))
				}
				val[k2] = vret
			}
		}
		ret = append(ret, val)
	}

	return ret, nil
}

// https://mailinabox.email/api-docs.html#operation/getDnsCustomRecordsForQNameAndType
// See comments on GetDnsCustomRecords() for explanation of return values
func (c *Context) GetDnsCustomRecordsForQNameAndType(qname, rtype string) (interface{}, error) {
	if !govalidator.IsDNSName(qname) {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "GetDnsCustomRecordsForQNameAndType",
			ErrorMsg:          "qname parameter is invalid",
		}
	}
	if rtype != "A" && rtype != "AAAA" && rtype != "CAA" && rtype != "CNAME" && rtype != "TXT" && rtype != "MX" && rtype != "SRV" && rtype != "SSHFP" && rtype != "NS" {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "GetDnsCustomRecordsForQNameAndType",
			ErrorMsg:          "rtype parameter is invalid",
		}
	}

	_, _, b, serr, err := c.doTheThing("GET", "/dns/custom/"+neturl.QueryEscape(qname)+"/"+rtype, "text/plain", nil, "GetDnsCustomRecordsForQNameAndType", false)
	if err != nil {
		return "", err
	} else if serr != nil {
		return string(b.(string)), serr
	}

	ret := []map[string]interface{}{}

	b2 := b.([]interface{})

	for _, v := range b2 {
		val := map[string]interface{}{}
		vv := v.(map[string]interface{})
		for k2, v2 := range vv {
			if k2 != "sort-order" {
				val[k2] = v2.(string)
			} else {
				vret := map[string]int{}
				vv2 := v2.(map[string]interface{})
				for k3, v3 := range vv2 {
					vret[k3] = int(math.Round(v3.(float64)))
				}
				val[k2] = vret
			}
		}
		ret = append(ret, val)
	}

	return ret, nil
}

// https://mailinabox.email/api-docs.html#operation/addDnsCustomRecord
func (c *Context) AddDnsCustomRecord(qname, rtype, value string) (string, error) {
	if !govalidator.IsDNSName(qname) {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "AddDnsCustomRecord",
			ErrorMsg:          "qname parameter is invalid",
		}
	}
	if rtype != "A" && rtype != "AAAA" && rtype != "CAA" && rtype != "CNAME" && rtype != "TXT" && rtype != "MX" && rtype != "SRV" && rtype != "SSHFP" && rtype != "NS" {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "AddDnsCustomRecord",
			ErrorMsg:          "rtype parameter is invalid",
		}
	}

	_, _, b, serr, err := c.doTheThing("POST", "/dns/custom/"+neturl.QueryEscape(qname)+"/"+rtype, "text/plain", value, "AddDnsCustomRecord", false)
	if err != nil {
		return "", err
	}

	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/updateDnsCustomRecord
func (c *Context) UpdateDnsCustomRecord(qname, rtype, value string) (string, error) {
	if !govalidator.IsDNSName(qname) {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "UpdateDnsCustomRecord",
			ErrorMsg:          "qname parameter is invalid",
		}
	}
	if rtype != "A" && rtype != "AAAA" && rtype != "CAA" && rtype != "CNAME" && rtype != "TXT" && rtype != "MX" && rtype != "SRV" && rtype != "SSHFP" && rtype != "NS" {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "UpdateDnsCustomRecord",
			ErrorMsg:          "rtype parameter is invalid",
		}
	}

	_, _, b, serr, err := c.doTheThing("PUT", "/dns/custom/"+neturl.QueryEscape(qname)+"/"+rtype, "text/plain", value, "UpdateDnsCustomRecord", false)
	if err != nil {
		return "", err
	}

	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/removeDnsCustomRecord
func (c *Context) RemoveDnsCustomRecord(qname, rtype, value string) (string, error) {
	if !govalidator.IsDNSName(qname) {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "RemoveDnsCustomRecord",
			ErrorMsg:          "qname parameter is invalid",
		}
	}
	if rtype != "A" && rtype != "AAAA" && rtype != "CAA" && rtype != "CNAME" && rtype != "TXT" && rtype != "MX" && rtype != "SRV" && rtype != "SSHFP" && rtype != "NS" {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "RemoveDnsCustomRecord",
			ErrorMsg:          "rtype parameter is invalid",
		}
	}

	_, _, b, serr, err := c.doTheThing("DELETE", "/dns/custom/"+neturl.QueryEscape(qname)+"/"+rtype, "text/plain", value, "RemoveDnsCustomRecord", false)
	if err != nil {
		return "", err
	}

	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/getDnsCustomARecordsForQName
// See comments on GetDnsCustomRecords() for explanation of return values
func (c *Context) GetDnsCustomARecordsForQName(qname string) (interface{}, error) {
	if !govalidator.IsDNSName(qname) {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "GetDnsCustomARecordsForQName",
			ErrorMsg:          "qname parameter is invalid",
		}
	}

	_, _, b, serr, err := c.doTheThing("GET", "/dns/custom/"+neturl.QueryEscape(qname), "text/plain", nil, "GetDnsCustomARecordsForQName", false)
	if err != nil {
		return "", err
	} else if serr != nil {
		return string(b.(string)), serr
	}

	ret := []map[string]interface{}{}

	b2 := b.([]interface{})

	for _, v := range b2 {
		val := map[string]interface{}{}
		vv := v.(map[string]interface{})
		for k2, v2 := range vv {
			if k2 != "sort-order" {
				val[k2] = v2.(string)
			} else {
				vret := map[string]int{}
				vv2 := v2.(map[string]interface{})
				for k3, v3 := range vv2 {
					vret[k3] = int(math.Round(v3.(float64)))
				}
				val[k2] = vret
			}
		}
		ret = append(ret, val)
	}

	return ret, nil
}

// https://mailinabox.email/api-docs.html#operation/addDnsCustomARecord
func (c *Context) AddDnsCustomARecord(qname, value string) (string, error) {
	if !govalidator.IsDNSName(qname) {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "AddDnsCustomARecord",
			ErrorMsg:          "qname parameter is invalid",
		}
	}

	_, _, b, serr, err := c.doTheThing("POST", "/dns/custom/"+neturl.QueryEscape(qname), "text/plain", value, "AddDnsCustomARecord", false)
	if err != nil {
		return "", err
	}

	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/updateDnsCustomARecord
func (c *Context) UpdateDnsCustomARecord(qname, value string) (string, error) {
	if !govalidator.IsDNSName(qname) {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "UpdateDnsCustomARecord",
			ErrorMsg:          "qname parameter is invalid",
		}
	}

	_, _, b, serr, err := c.doTheThing("PUT", "/dns/custom/"+neturl.QueryEscape(qname), "text/plain", value, "UpdateDnsCustomARecord", false)
	if err != nil {
		return "", err
	}

	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/removeDnsCustomARecord
func (c *Context) RemoveDnsCustomARecord(qname, value string) (string, error) {
	if !govalidator.IsDNSName(qname) {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "RemoveDnsCustomARecord",
			ErrorMsg:          "qname parameter is invalid",
		}
	}

	_, _, b, serr, err := c.doTheThing("DELETE", "/dns/custom/"+neturl.QueryEscape(qname), "text/plain", value, "RemoveDnsCustomARecord", false)
	if err != nil {
		return "", err
	}

	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/getDnsDump
// Returns [][]interface{} if err is not nil, where interface{} may be a string
// hostname or it may be a map[string]string with the keys "explanation",
// "qname", "rtype", and "value".
//
// Example:
//	[
//		[
//			"box.example.com",
//			{
//				"qname": "asdf.box.example.com",
//				"rtype": "A",
//				"value": "1.2.3.4",
//				"explanation": "(Set by user.)"
//			}
//		],
//		[
//			"box2.example.com",
//			{
//				"qname": "asdf.box2.example.com",
//				"rtype": "A",
//				"value": "1.2.3.5",
//				"explanation": "(Set by user.)"
//			}
//		]
//	]
func (c *Context) GetDnsDump() (interface{}, error) {
	_, _, b, serr, err := c.doTheThing("GET", "/dns/dump", "text/plain", nil, "GetDnsDump", false)
	if err != nil {
		return "", err
	} else if serr != nil {
		return string(b.(string)), serr
	}

	ret := [][]interface{}{}

	rb := b.([]interface{})
	for _, v1 := range rb {
		iv := []interface{}{}
		iv1 := v1.([]interface{})
		for _, v2 := range iv1 {
			switch t := v2.(type) {
			case string:
				iv = append(iv, t)
			default:
				iiv := []map[string]string{}
				v2i := v2.([]interface{})
				for _, viiv := range v2i {
					viiv2 := viiv.(map[string]interface{})
					iv3 := map[string]string{}
					for kiiiv, viiiv := range viiv2 {
						iv3[kiiiv] = viiiv.(string)
					}
					iiv = append(iiv, iv3)
				}
				iv = append(iv, iiv)
			}
		}
		ret = append(ret, iv)
	}

	return ret, nil
}

// https://mailinabox.email/api-docs.html#operation/getSSLStatus
// Returns string if err != nil and map[string][]interface{}{} if no error.
func (c *Context) GetSSLStatus() (interface{}, error) {
	_, _, b, serr, err := c.doTheThing("GET", "/ssl/status", "text/plain", nil, "GetSSLStatus", false)
	if err != nil {
		return "", err
	} else if serr != nil {
		return string(b.(string)), serr
	}

	ret := map[string][]interface{}{}

	rb := b.(map[string]interface{})
	for k, v := range rb {
		val := []interface{}{}
		ifaceslices := v.([]interface{})
		for _, item := range ifaceslices {
			switch t := item.(type) {
			case string:
				val = append(val, t)
			default:
				innermap := map[string]interface{}{}
				innervalmap := item.(map[string]interface{})
				for ik, iv := range innervalmap {
					innermap[ik] = iv.(string)
				}
				val = append(val, innermap)
			}
		}
		ret[k] = val
	}

	return ret, nil
}

// https://mailinabox.email/api-docs.html#operation/generateSSLCSR
func (c *Context) GenerateSSLCSR(domain, countrycode string) (string, error) {
	if !govalidator.IsDNSName(domain) {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "GenerateSSLCSR",
			ErrorMsg:          "domain parameter is invalid",
		}
	}
	if _, ok := country.ByAlpha2CodeStr(countrycode); !ok {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "GenerateSSLCSR",
			ErrorMsg:          "countrycode parameter is invalid",
		}
	}

	body := make(map[interface{}]interface{})
	body["countrycode"] = countrycode
	_, _, b, serr, err := c.doTheThing("POST", "/ssl/csr/"+neturl.QueryEscape(domain), "application/x-www-form-urlencoded", body, "GenerateSSLCSR", false)
	if err != nil {
		return "", err
	}

	return string(b.(string)), serr

}

// https://mailinabox.email/api-docs.html#operation/installSSLCertificate
func (c *Context) InstallSSLCertificate(domain, cert string, chain interface{}) (string, error) {
	if !govalidator.IsDNSName(domain) {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "InstallSSLCertificate",
			ErrorMsg:          "domain parameter is invalid",
		}
	}

	bchain := ""
	if chain != nil {
		bchain = chain.(string)
	}

	body := make(map[interface{}]interface{})
	body["domain"] = domain
	body["cert"] = cert
	body["chain"] = bchain
	_, _, b, serr, err := c.doTheThing("POST", "/ssl/install", "application/x-www-form-urlencoded", body, "InstallSSLCertificate", false)
	if err != nil {
		return "", err
	}

	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/provisionSSLCertificates
func (c *Context) ProvisionSSLCertificates() (interface{}, error) {
	_, _, b, serr, err := c.doTheThing("POST", "/ssl/provision", "text/plain", nil, "ProvisionSSLCertificates", false)
	if err != nil {
		return "", err
	} else if serr != nil {
		return string(b.(string)), serr
	}

	ret := map[string][]map[string]interface{}{}
	rb := b.(map[string]interface{})
	for k1, v1 := range rb {
		ret[k1] = []map[string]interface{}{}
		v1i := v1.([]interface{})
		for _, v2 := range v1i {
			// The return value unmarshals into a weird situation where there
			// is a leftover empty string, so we continue on that case
			switch v2.(type) {
			case string:
				continue
			}
			vi := v2.(map[string]interface{})
			for k3, v3 := range vi {
				switch t := v3.(type) {
				case string:
					vi[k3] = t
				default:
					vii := []string{}
					v3c := v3.([]interface{})
					for _, v4 := range v3c {
						vii = append(vii, v4.(string))
					}
					vi[k3] = vii
				}
			}
			ret[k1] = append(ret[k1], vi)
		}
	}

	return ret, nil
}

// https://mailinabox.email/api-docs.html#operation/getWebDomains
func (c *Context) GetWebDomains() (interface{}, error) {
	_, _, b, serr, err := c.doTheThing("GET", "/web/domains", "text/plain", nil, "GetWebDomains", false)
	if err != nil {
		return "", err
	} else if serr != nil {
		return string(b.(string)), serr
	}

	ret := []map[string]interface{}{}
	vb := b.([]interface{})
	for _, v1 := range vb {
		v1i := v1.(map[string]interface{})
		nr := map[string]interface{}{}
		for k2, v2 := range v1i {
			switch t := v2.(type) {
			case string, bool:
				nr[k2] = t
			default:
				vii := []string{}
				vbii := v2.([]interface{})
				for _, v3 := range vbii {
					vii = append(vii, string(v3.(string)))
				}
				nr[k2] = vii
			}
		}
		ret = append(ret, nr)
	}

	return ret, nil
}

// https://mailinabox.email/api-docs.html#operation/updateWeb
func (c *Context) UpdateWeb() (string, error) {
	_, _, b, serr, err := c.doTheThing("POST", "/web/update", "text/plain", nil, "UpdateWeb", false)
	if err != nil {
		return "", err
	}
	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/mfaStatus
// The docs say that enabled_mfa returns a single object, but in fact it
// returns an array of objects.
// Similarly, new_mfa does not return a map[string]string as the docs say, but
// instead returns a map[string]map[string]string, with the outer map having
// only the key "totp". This is likely so that in the future, multiple kinds of
// 2FA can be added, but the docs make no mention of this.
func (c *Context) MfaStatus() (interface{}, error) {
	_, _, b, serr, err := c.doTheThing("POST", "/mfa/status", "text/plain", nil, "MfaStatus", false)
	if err != nil {
		return "", err
	} else if serr != nil {
		return string(b.(string)), serr
	}

	ret := map[string]interface{}{}
	rb := b.(map[string]interface{})
	for k, v := range rb {
		if v == nil {
			ret[k] = nil
		} else {
			switch v.(type) {
			case []interface{}:
				vbi := []map[string]string{}
				vbii := v.([]interface{})
				for _, v2 := range vbii {
					v2i := v2.(map[string]interface{})
					vbiii := map[string]string{}
					for k3, v3 := range v2i {
						switch t := v3.(type) {
						case float64:
							vbiii[k3] = strconv.Itoa(int(t))
						case float32:
							vbiii[k3] = strconv.Itoa(int(t))
						case int:
							vbiii[k3] = strconv.Itoa(t)
						default:
							vbiii[k3] = v3.(string)
						}
					}
					vbi = append(vbi, vbiii)
				}
				ret[k] = vbi
			default:
				vbi := map[string]map[string]string{}
				vbii := v.(map[string]interface{})
				for k2, v2 := range vbii {
					v2i := v2.(map[string]interface{})
					vbiii := map[string]string{}
					for k3, v3 := range v2i {
						vbiii[k3] = v3.(string)
					}
					vbi[k2] = vbiii
				}
				ret[k] = vbi
			}
		}
	}
	return ret, nil
}

// https://mailinabox.email/api-docs.html#operation/mfaTotpEnable
// The docs use the word "code" but the actual parameter is "token".
// (You can discover the real API by reading the javascript used in the admin
// panel page of your MIAB instance.)
// Also, the server will return 400 status if the secret is not a base32 string
// of length 32.
func (c *Context) MfaTotpEnable(secret, code string, label interface{}) (string, error) {
	dst := make([]byte, base32.StdEncoding.DecodedLen(len(secret)))
	if _, er := base32.StdEncoding.Decode(dst, []byte(secret)); er != nil || len(secret) != 32 {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "MfaTotpEnable",
			ErrorMsg:          "secret must be a base32 string of length 32",
		}
	}

	body := make(map[interface{}]interface{})
	body["secret"] = secret
	body["token"] = code
	if label != nil {
		l2 := label.(string)
		if l2 != "" {
			body["label"] = l2
		}
	}
	_, _, b, serr, err := c.doTheThing("POST", "/mfa/totp/enable", "application/x-www-form-urlencoded", body, "MfaTotpEnable", false)
	if err != nil {
		return "", err
	}
	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/mfaTotpDisable
// mfa_id can be the id or the label, or nil to disable 2FA for all users;
// user can be nil or string user
func (c *Context) MfaTotpDisable(mfa_id, user interface{}) (string, error) {
	u1 := ""
	m1 := ""
	if user != nil {
		ui := user.(string)
		if ui != "" {
			u1 = ui
		}
	}
	if mfa_id != nil {
		var mi string
		switch t := mfa_id.(type) {
		case float64:
			mi = strconv.Itoa(int(t))
		case float32:
			mi = strconv.Itoa(int(t))
		case int:
			mi = strconv.Itoa(t)
		case string:
			mi = t
		default:
			mi = string(t.(string))
		}
		if mi != "" {
			m1 = mi
		}
	}
	body := make(map[interface{}]interface{})
	if m1 != "" {
		body["mfa_id"] = m1
	}
	if u1 != "" {
		body["user"] = u1
	}
	_, _, b, serr, err := c.doTheThing("POST", "/mfa/disable", "application/x-www-form-urlencoded", body, "MfaTotpDisable", false)
	if err != nil {
		return "", err
	}

	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/getSystemStatus
func (c *Context) GetSystemStatus() (interface{}, error) {
	_, _, b, serr, err := c.doTheThing("POST", "/system/status", "text/plain", nil, "GetSystemStatus", false)
	if err != nil {
		return "", err
	} else if serr != nil {
		return string(b.(string)), serr
	}

	rb := []map[string]interface{}{}
	vb := b.([]interface{})
	for _, v := range vb {
		vi := v.(map[string]interface{})
		vbi := map[string]interface{}{}
		for k2, v2 := range vi {
			if k2 != "extra" {
				vbi[k2] = v2.(string)
			} else {
				vbii := []map[string]interface{}{}
				v2i := v2.([]interface{})
				for _, v3 := range v2i {
					v3i := v3.(map[string]interface{})
					vbiii := map[string]interface{}{}
					for k4, v4 := range v3i {
						if k4 == "monospace" {
							vbiii[k4] = v4.(bool)
						} else if k4 == "text" {
							vbiii[k4] = v4.(string)
						} else {
							vbiii[k4] = v4 // any additional []map[string]interface{} values under "extra" are unknown types, so the value is left as an uncast interface{}, and we leave it to the client to type-check if the result isn't just being converted to json text
						}
					}
					vbii = append(vbii, vbiii)
				}
				vbi[k2] = vbii
			}
		}
		rb = append(rb, vbi)
	}

	return rb, nil
}

// https://mailinabox.email/api-docs.html#operation/getSystemVersion
func (c *Context) GetSystemVersion() (string, error) {
	_, _, b, serr, err := c.doTheThing("GET", "/system/version", "text/plain", nil, "GetSystemVersion", false)
	if err != nil {
		return "", err
	}
	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/getSystemUpstreamVersion
func (c *Context) GetSystemUpstreamVersion() (string, error) {
	_, _, b, serr, err := c.doTheThing("POST", "/system/latest-upstream-version", "text/plain", nil, "GetSystemUpstreamVersion", false)
	if err != nil {
		return "", err
	}
	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/getSystemUpdates
func (c *Context) GetSystemUpdates() (string, error) {
	_, _, b, serr, err := c.doTheThing("GET", "/system/updates", "text/plain", nil, "GetSystemUpdates", false)
	if err != nil {
		return "", err
	}
	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/updateSystemPackages
func (c *Context) UpdateSystemPackages() (string, error) {
	_, _, b, serr, err := c.doTheThing("POST", "/system/update-packages", "text/plain", nil, "UpdateSystemPackages", false)
	if err != nil {
		return "", err
	}
	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/getSystemPrivacyStatus
// return value will be string if there's an error, but will be a bool if err == nil
func (c *Context) GetSystemPrivacyStatus() (interface{}, error) {
	_, _, b, serr, err := c.doTheThing("GET", "/system/privacy", "text/plain", nil, "GetSystemPrivacyStatus", true)
	if err != nil {
		return "", err
	} else if serr != nil {
		return string(b.(string)), serr
	}

	ret, err2 := strconv.ParseBool(strings.TrimSpace(string(b.(string))))
	if err2 != nil {
		return string(b.(string)), err2
	}
	return ret, nil
}

// https://mailinabox.email/api-docs.html#operation/updateSystemPrivacy
func (c *Context) UpdateSystemPrivacy(value string) (string, error) {
	if value != "private" && value != "off" {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "UpdateSystemPrivacy",
			ErrorMsg:          "value parameter must be \"private\" or \"off\"",
		}
	}
	body := make(map[interface{}]interface{})
	body["value"] = value
	_, _, b, serr, err := c.doTheThing("POST", "/system/privacy", "application/x-www-form-urlencoded", body, "UpdateSystemPrivacy", false)
	if err != nil {
		return "", err
	}
	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/getSystemRebootStatus
func (c *Context) GetSystemRebootStatus() (interface{}, error) {
	_, _, b, serr, err := c.doTheThing("GET", "/system/reboot", "text/plain", nil, "GetSystemRebootStatus", true)
	if err != nil {
		return "", err
	} else if serr != nil {
		return string(b.(string)), serr
	}

	ret, err2 := strconv.ParseBool(strings.TrimSpace(string(b.(string))))
	if err2 != nil {
		return string(b.(string)), err2
	}
	return ret, nil
}

// https://mailinabox.email/api-docs.html#operation/rebootSystem
func (c *Context) RebootSystem() (string, error) {
	_, _, b, serr, err := c.doTheThing("POST", "/system/reboot", "text/plain", nil, "RebootSystem", false)
	if err != nil {
		return "", err
	}
	return string(b.(string)), serr
}

// https://mailinabox.email/api-docs.html#operation/getSystemBackupStatus
func (c *Context) GetSystemBackupStatus() (interface{}, error) {
	_, _, b, serr, err := c.doTheThing("GET", "/system/backup/status", "text/plain", nil, "GetSystemBackupStatus", false)
	if err != nil {
		return "", err
	} else if serr != nil {
		return string(b.(string)), serr
	}

	ret := map[string]interface{}{}
	vb := b.(map[string]interface{})
	for k, v := range vb {
		if k == "unmatched_file_size" {
			switch t := v.(type) {
			case float64:
				ret[k] = int(t)
			case float32:
				ret[k] = int(t)
			case int:
				ret[k] = t
			}
		} else if k == "error" {
			ret[k] = v.(string)
		} else if k != "backups" {
			ret[k] = v
		} else {
			vbi := []map[string]interface{}{}
			vi := v.([]interface{})
			for _, v2 := range vi {
				v2i := v2.(map[string]interface{})
				vii := map[string]interface{}{}
				for k3, v3 := range v2i {
					switch t := v3.(type) {
					case bool, int, int32, string:
						vii[k3] = t
					default:
						vii[k3] = v3
					}
				}
				vbi = append(vbi, vii)
			}
			ret[k] = vbi
		}
	}

	return ret, nil
}

// https://mailinabox.email/api-docs.html#operation/getSystemBackupConfig
func (c *Context) GetSystemBackupConfig() (interface{}, error) {
	_, _, b, serr, err := c.doTheThing("GET", "/system/backup/config", "text/plain", nil, "GetSystemBackupConfig", false)
	if err != nil {
		return "", err
	} else if serr != nil {
		return string(b.(string)), serr
	}

	return b.(map[string]interface{}), nil
}

// https://mailinabox.email/api-docs.html#operation/updateSystemBackupConfig
// This has never actually been tested, because I didn't want to mess with my
// backups. (Everything else was tested on my personal MIAB setup that I
// actually use.) So BE CAREFUL when using this function because it might not
// work...
func (c *Context) UpdateSystemBackupConfig(target, target_user, target_pass string, min_age int) (string, error) {
	if min_age < 1 {
		return "", MiabError{
			IsHTTPStatusError: false,
			CallingFunction:   "UpdateSystemBackupConfig",
			ErrorMsg:          "min_age param must be >= 1",
		}
	}

	body := make(map[interface{}]interface{})
	body["target"] = target
	body["target_user"] = target_user
	body["target_pass"] = target_pass
	body["min_age"] = strconv.Itoa(min_age)

	_, _, b, serr, err := c.doTheThing("POST", "/system/backup/config", "application/x-www-form-urlencoded", body, "GetSystemBackupConfig", false)
	if err != nil {
		return "", err
	}
	return string(b.(string)), serr
}
