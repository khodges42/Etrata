# Etrata
CI Vuln Scanner

## What is it?
This is a lightweight python script that will load/read a directory of CVEs and allow you to search on them.

## Usage
`etrata -n struts -v 2.3.32`

```>{'CVE-2017-12611',
 >'CVE-2017-9787',
 >'CVE-2017-9791',
 >'CVE-2017-9793',
 >'CVE-2017-9804',
 >'CVE-2017-9805',
 >'CVE-2018-11776',
 >'CVE-2018-1327'}
 ```

`etrata -f ~/code/production/webserver/requirements.txt`
```  
    bcrypt 3.1.4 : ✓
    cryptography 0.1.0 : {'CVE-2016-9243'}
    pyOpenSSL 18.0.0 : ✓
    requests 2.19.1 : ✓
    urllib3 1.23 : {'CVE-2019-11236', 'CVE-2019-11324'}
```

## Disclaimer
Don't use this for something sketchy. [There are better tools for that](https://github.com/NullArray/AutoSploit)
