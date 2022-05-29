# miabhttp

### Mail-in-a-box HTTP API client for Go

This library was designed for use with Mail-in-a-box **v56** using the API [documentation](https://mailinabox.email/api-docs.html) generated from the MIAB repo [at this commit](https://raw.githubusercontent.com/mail-in-a-box/mailinabox/eeee712cf3ad4d337479956f2c036071cc7e93c9/api/mailinabox.yml).

That documentation may no longer be accurate. Where the documentation is known to be inaccurate against my own testing of the actual API, I have noted that in the comments for the affected function.

This library should not be considered safe, secure, or well-tested, and you must use it at your own risk. I am not the best programmer to begin with, *and this is the first Go I have ever written*. So, buyer beware...

To use it, you must first create a miabhttp.Context instance, which holds information about how to login to your MIAB server. You can use a username/password combo, or generate an API key from a username and password, and create a Context with a username and API key, omitting the password. If you make an API key, it is recommended to run the Logout() function when you have finished, in order to expire the API key immediately.

Many functions return an interface{}. This is usually because the return value may be a string, or may be a map[string]interface{}, depending on the returned data from the server. Often, when JSON is returned, a map[string]interface{} may be returned upon success, but a string may be returned upon failure. It is up to you the user/client to look at how the function works as well as my comments about the function and determine the best way to handle these unknown return values.

Errors returned by other libraries are returned back through. Errors returned by my library are wrapped in a very simple MiabError struct, whose internals can be accessed like this (where c is a Context):

```
if result, err := c.GetMailAliases("invalid_format"); err != nil {
    if errors.As(err, &miabhttp.MiabError{}) {
        miaberror := err.(miabhttp.MiabError)
        fmt.Println("The error occured in the miabhttp function " + miaberror.CallingFunction)
    }
}
```

Additionally worth noting: I have noticed that the server returns HTTP 400 errors when the request is sane and correct, but the action cannot be completed. For example, trying to remove two-factor authentication from a user that does not have 2FA on their account. This is confusing as a client, because some functions are idempotent and return success in these instances, and other functions return HTTP 400. I mention this solely for your benefit, because it frustrated me a lot while testing this library.

Function names are exactly the same as they are in the API URLs, expect for the first letter being capitalized. Parameters are the same, and return values are the same. For the most part, you should be able to intuit everything based on the documentation and my comments. The only thing that may take getting used to is how I return interfaces{} for JSON returns. See the example code below.

Example usage:

```
myUser := "foo@example.com"
myMiabServer := "box.example.com"

// The MIAB Login API may return successfully but no API key if you enter a bad
// username/password combo. I have chosen to mimic the API as closely as possible,
// so I also return no error in such an event. Therefore, for this function, you
// must also check if the result is an empty string.
apikey, err := miabhttp.LoginAndReturnAPIKey(myMiabServer, "admin", myUser, "my_secret_password", "", true)
if err != nil || apikey == "" {
  os.Exit(1)
}

miabContext, err := miabhttp.CreateMiabContext(myMiabServer, "admin", myUser, "", apikey, "")
if err != nil {
  os.Exit(1)
}
defer miabContext.Logout()


// Now you have a Context to call any function with

// Get a string (on error) or a []map[string]interface{} on success, since
// this is the format returned by the server, and this library seeks to
// be an accurate implementation
result, err := miabContext.GetDnsCustomARecordsForQName("www.example.com")
if err != nil {
  os.Stderr.WriteString("The website returned the text: " + result.(string) +
    "with an error of: " + err.Error())
  os.Exit(1)
}

// Because we map unknown json, we must explicitly cast the result to the
// format we know it's in (based on the API docs and my comments).
// For example, here, we know the result is a slice with only one value, so
// we get index 0 and cast the value's interface{} to a string since we know
// it's a string.
myIPaddr := result.([]map[string]interface{})[0]["value"].(string)
fmt.Println("The IP for www.example.com is: " + myIPaddr)


// Change/update the DNS record
_, err := miabContext.UpdateDnsCustomARecord("www.example.com", "1.2.3.4")
if err != nil {
  os.Exit(1)
}
// Update Success!


// Do whatever else we want to do, then return/exit and let our defered
// Logout() invalidate the API key.
```
