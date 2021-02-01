# PDFSign
Basic command line tool for signing and certifying PDF Files using a PKCS12 certificate,
a certificate from the windows store or using a PKCS11 compatible hardware token.

## Notes
This is a command line tool that allows signing and/or timestamping of pdf files using certificates.
The actual PDF manipulation is performed using the itextsharp library v5.5.
This is a fork of (https://github.com/IcoDeveloper/PDFSign) with some added features and bug fixes
(hardware token support, LTV, certification, TSA authentication).
This tool was originaly published by Martin Bene on [codeplex](https://archive.codeplex.com/?p=pdfsign)


The signing certificate can can either be provided as a PKCS12 file, it can come from 
the windows certificate store or it can come from a hardware token.

In order to use a certificate from the windows store, the certificate must
  - have the private key marked as exportable
  - the user running pdfsign must have read access to the private key

In order to use a hardware token, the token must support PKCS11 and the path to the driver DLL
implementing the PKCS11 api must be provided.
For example, for SafeNet eToken this would be C:\Windows\System32\eTPKCS11.dll

It's also possible to only timestamp the document using a trusted timestamping service (TSA)
without signing it (for this, simply don't provide any certificate but do provide a tsa url).
  
In Addition to nuget packages, the build process uses Microsofts [ILMerge](http://www.microsoft.com/download/en/details.aspx?displaylang=en&id=17630) 
tool to produce a consolidated single binary including all dlls. 

LTV (long term validation) is enabled by default. This embeds the certificate-chain, certificate revocation lists
and OSCP replies into the document so that the signature remains verifiable also beyond the validity of the
signing certificate. This can significantly increase filesize however if certificates in the chain don't use
OSCP and instead reference large CRL files. LTV can be disabled with -ltv-
NOTE: If a TSA URL is provided and LTV is enabled, the programm will request two timestamp tokens from the TSA.
The first one is only used to extract the trust chain of the token, which is needed to enable LTV for the second
token, which will actually timestamp the document. This way Adobe Reader will recognize the Timestamp as LTV enabled.

## usage
```
pdfsign v1.5.0, (c) 2021 Mabulous GmbH
powered by:
pdfsign v1.3.0, (c) 2019 icomedias GmbH
iTextSharp 5.5 Copyright (C) 1999-2018 by iText Group NV
Pkcs11Interop Copyright (C) 2012-2021 The Pkcs11Interop Project
Usage: pdfsign [OPTIONS]
Sign a PDF file using a signing certificate

Options:
  -i, --infile=VALUE         PDF input file
  -o, --outfile=VALUE        Output file for signed PDF
  -b, --backpage=VALUE       PDF file to append to infile before placing
                               signature (optional)
  -p, --password=VALUE       Import password for signing certificate or PIN for
                               pkcs11 token
      --pkcs11lib=VALUE      Path to PKCS11 Library DLL. If specified, PKCS11
                               Token will be used for signing
      --tokenserial=VALUE    The Serial of the PKCS11 token to use. Optional if
                               only a single Token is connected
      --certid=VALUE         The ID (CKA_ID) of the certificate on the token to
                               use. Optional if only a single certificate is
                               stored on the token
      --thumbprint=VALUE     Thumbprint for signing certificate from windows
                               store
      --store=VALUE          Store for signing certificate from windows (
                               CurrentUser or LocalMachine (default
                               LocalMachine))
  -c, --certfile=VALUE       PKCS12 signing certificate
  -r, --reason=VALUE         Signature reason (gets embedded in signature)
  -l, --location=VALUE       Signature location (gets embedded in signature)
  -t, --contact=VALUE        Signature contact (gets embedded in signature)
  -s, --show                 Show signature (signature field visible), on: -s+
                               off: -s-, default on
      --page=VALUE           Page of the document to place signature: 1..n,
                               last. default 1
      --template=VALUE       Template for the signature text. use \n for line
                               breaks, [name], [date] for substitution
      --dateformat=VALUE     Format for [date] substitution when using template
      --showvalidity         Show signature validity (deprecated), on: -
                               showvalidity+ off: -showvalidity-, default off
      --tsa=VALUE            URL of rfc3161 TSA (Time Stamping Authority)
      --tsauser=VALUE        If selected TSA server requires credentials, enter
                               username (optional)
      --tsapass=VALUE        If selected TSA server requires credentials, enter
                               password (optional)
      --ltv                  Enables Long Term Validation, on: -ltv+, off: -ltv-
                               , default on
      --certlevel=VALUE      Certification Level. 0: Not certified, 1: No
                               changes allowed, 2: Only Allow Form-Filling, 3:
                               Only Allow Form-Filling & Annotations, default 0
      --width=VALUE          Signature width, default 180
      --height=VALUE         Signature height, default 80
      --hsep=VALUE           Horizontal seperation of signatures, default 10
      --vsep=VALUE           Vertical seperation of signatures, default 10
      --hoffset=VALUE        Horizontal offset of signatures, default 350
      --voffset=VALUE        Vertical offset of signatures, default 5
      --cols=VALUE           Number of signature columns, default 1
  -v, --verbose              Enable log output, on: -v+, off: -v-, default on
  -m, --multi                Allow multiple signatures, on: -m+, off: -m-,
                               default on
  -h, -?, --help             Show this help message and exit
Return Values:
         0: Success
        -1: Bad Command Line Option(s)
        -2: Error processing signing certificate
        -3: Error getting secret key
        -4: Error getting certificate chain
        -5: Error processing input file
        -6: Error opening output file
        -7: Error generating signature
        -8: Error using PKCS11 token```

## multiple signatures

Multiple signatures are supported; if you leave signature visibility turned on, additional signatures get 
seperate signature field names (Signature, Signature1, Signature2...) and are automatically positioned as 
a grid with --cols columns from left to right and bottom to top.

## certification

By default the PDF is only signed, not certified (which allows to add additional signatures later).
To certify, set --certlevel to something other than 0

## Trusted Timestamping

To add a trusted timestamp (which allows to prove that the document was not altered after the date of
the timestamp) set --tsa to a URL of a RFC 3161 TSA-server.
If the server requires login, additionally define --tsauser and --tsapass