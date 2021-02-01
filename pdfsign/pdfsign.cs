/*
/*
 * pdfsign.cs: digitaly sign pdf files
 * 
 * Copyright (C) 2021 Mabulous GmbH
 *
 *
 * based on:
 * pdfSign 1.3.0 Copyright (C) 2019 icomedias GmbH
 * code/samples from itext project by:
 * Copyright (C) 1999-2011 by 1T3XT BVBA, Bruno Lowagie and Paulo Soares.
 * updated to use itextsharp 5.5 libary
 * Copyright (C) 1999-2018 by iText Group NV
 * Pkcs11Interop Copyright (C) 2012-2021 The Pkcs11Interop Project
 *
 * This program is licensed unter the terms of the 
 * GNU Affero General Public License v3.0, see LICENSE File
 */

using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Mono.Options;
using Net.Pkcs11Interop.PDF;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;

namespace pdfsign
{
    class Program
    {
        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("pdfsign v1.6.0, (c) 2021 Mabulous GmbH");
            Console.WriteLine("powered by:");
            Console.WriteLine("pdfsign v1.3.0, (c) 2019 icomedias GmbH");
            Console.WriteLine("iTextSharp 5.5 Copyright (C) 1999-2018 by iText Group NV");
            Console.WriteLine("Pkcs11Interop Copyright (C) 2012-2021 The Pkcs11Interop Project");
            Console.WriteLine("Usage: pdfsign [OPTIONS]");
            Console.WriteLine("Sign a PDF file using a signing certificate");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
            Console.WriteLine("Return Values:");
            Console.WriteLine("\t {0}: Success", (int)Retvals.SUCCESS);
            Console.WriteLine("\t{0}: Bad Command Line Option(s)", (int)Retvals.ERR_PARAMETER);
            Console.WriteLine("\t{0}: Error processing signing certificate", (int)Retvals.ERR_CERT);
            Console.WriteLine("\t{0}: Error getting secret key", (int)Retvals.ERR_KEY);
            Console.WriteLine("\t{0}: Error getting certificate chain", (int)Retvals.ERR_CHAIN);
            Console.WriteLine("\t{0}: Error processing input file", (int)Retvals.ERR_INPUT);
            Console.WriteLine("\t{0}: Error opening output file", (int)Retvals.ERR_OUTPUT);
            Console.WriteLine("\t{0}: Error generating signature", (int)Retvals.ERR_SIGN);
            Console.WriteLine("\t{0}: Error using PKCS11 token", (int)Retvals.ERR_TOKEN);
        }

        enum Retvals
        {
            SUCCESS = 0,
            ERR_PARAMETER = -1,
            ERR_CERT = -2,
            ERR_KEY = -3,
            ERR_CHAIN = -4,
            ERR_INPUT = -5,
            ERR_OUTPUT = -6,
            ERR_SIGN = -7,
            ERR_TOKEN = -8
        }

        static int Main(string[] args)
        {
            int width = 180;
            int height = 80;
            int cols = 1;
            int hsep = 10;
            int vsep = 10;
            int hoffset = 350;
            int voffset = 5;
            int pageno = 1;
            int certification_level = PdfSignatureAppearance.NOT_CERTIFIED;
            string pageParam = "1";
            string infile = null;
            string backpage = null;
            string outfile = null;
            bool use_pkcs11 = false;
            string pkcs11_library_path = null;
            string token_serial = null;
            string cert_id = null;
            string certfile = null;
            string thumbprint = null;
            string tsa_url = null;
            string tsa_user = null;
            string tsa_pass = null;
            string store = "LocalMachine";
            string template = null;
            string dateformat = "G"; 
            string password = null;
            string reason = null;
            string location = null;
            string contact = null;
            bool show_signature = true;
            bool show_validity = false;
            bool multi_signature = true;
            bool use_ltv = true;
            bool show_help = false;
            bool verbose = true;
            bool timestamp_only = false;

            Retvals retval;

            var p = new OptionSet() {
                { "i|infile=", "PDF input file", v => infile = v },
                { "o|outfile=", "Output file for signed PDF", v => outfile = v },
                { "b|backpage=", "PDF file to append to infile before placing signature (optional)", v => backpage = v },
                { "p|password=", "Import password for signing certificate or PIN for pkcs11 token", v => password = v },
                { "pkcs11lib=", "Path to PKCS11 Library DLL. If specified, PKCS11 Token will be used for signing", v => pkcs11_library_path = v },
                { "tokenserial=", "The Serial of the PKCS11 token to use. Optional if only a single Token is connected", v => token_serial = v},
                { "certid=", "The ID (CKA_ID) of the certificate on the token to use. Optional if only a single certificate is stored on the token", v => cert_id = v},             
                { "thumbprint=", "Thumbprint for signing certificate from windows store", v => thumbprint = v },
                { "store=", "Store for signing certificate from windows (CurrentUser or LocalMachine (default LocalMachine))", v => store = v },
                { "c|certfile=", "PKCS12 signing certificate", v => certfile = v },
                { "r|reason=", "Signature reason (gets embedded in signature)", v => reason = v },
                { "l|location=", "Signature location (gets embedded in signature)", v => location = v },
                { "t|contact=", "Signature contact (gets embedded in signature)", v => contact = v },
                { "s|show", "Show signature (signature field visible), on: -s+ off: -s-, default on", v => show_signature = v != null },
                { "page=", "Page of the document to place signature: 1..n, last. default 1", v => pageParam = v },
                { "template=", "Template for the signature text. use \\n for line breaks, [name], [date] for substitution", v => template = v },
                { "dateformat=", "Format for [date] substitution when using template", v => dateformat = v },
                { "showvalidity", "Show signature validity (deprecated), on: -showvalidity+ off: -showvalidity-, default off", v => show_validity = v != null },
                { "tsa=", "URL of rfc3161 TSA (Time Stamping Authority)", v => tsa_url = v },
                { "tsauser=", "If selected TSA server requires credentials, enter username (optional)", v => tsa_user = v },
                { "tsapass=", "If selected TSA server requires credentials, enter password (optional)", v => tsa_user = v },
                { "ltv", "Enables Long Term Validation, on: -ltv+, off: -ltv-, default on", v => use_ltv = v != null },
                { "certlevel=", "Certification Level. 0: Not certified, 1: No changes allowed, 2: Only Allow Form-Filling, 3: Only Allow Form-Filling & Annotations, default 0", (int v) => certification_level = v},
                { "width=", "Signature width, default 180", (int v) => width = v},
                { "height=", "Signature height, default 80", (int v) => height = v},
                { "hsep=", "Horizontal seperation of signatures, default 10", (int v) => hsep=v},
                { "vsep=", "Vertical seperation of signatures, default 10", (int v) => vsep=v},
                { "hoffset=", "Horizontal offset of signatures, default 350", (int v) => hoffset=v},
                { "voffset=", "Vertical offset of signatures, default 5", (int v) => voffset=v},
                { "cols=","Number of signature columns, default 1", (int v) => cols = v},
                { "v|verbose", "Enable log output, on: -v+, off: -v-, default on", v => verbose = v != null },
                { "m|multi", "Opens document in 'Append mode', leaving existing signatures untouched, on: -m+, off: -m-, default on", v => multi_signature = v != null },
                { "h|?|help", "Show this help message and exit", v => show_help = v != null },
            };

            retval = Retvals.ERR_PARAMETER; // Option Error
            List<string> extra;
            try
            {
                extra = p.Parse(args);

                if(!verbose)
                {
                    Console.SetOut(TextWriter.Null);
                }

                if (show_help)
                {
                    ShowHelp(p);
                    return (int)Retvals.SUCCESS;
                }

                if (extra.Count > 0)
                    throw new OptionException("uncrecognised parameters", string.Join(" ", extra.ToArray()));

                if (infile == null)
                    throw new OptionException("required parameter {0} missing", "infile");

                if (outfile == null)
                    throw new OptionException("required parameter {0} missing", "outfile");

                if (!String.IsNullOrEmpty(backpage) && !File.Exists(backpage))
                    throw new OptionException("backpage file {0} does not exist", backpage);

                int cert_methods = (String.IsNullOrEmpty(pkcs11_library_path) ? 0 : 1) +
                                   (String.IsNullOrEmpty(certfile) ? 0 : 1) +
                                   (String.IsNullOrEmpty(thumbprint) ? 0 : 1);
                if(cert_methods > 1)
                {
                    throw new OptionException("must use only one of {0}", "pkcs11lib, thumbprint, certfile");
                } 
                if (cert_methods == 0)
                {
                    if(tsa_url == null)
                        throw new OptionException("If you don't provide a certificate, you must provide a {0}", "tsa");
                    else
                        timestamp_only = true;
                }

                if(reason == null)
                {
                    if(timestamp_only)
                        reason = "Timestamping";
                    else
                        reason = "Proof of authenticity";
                }

                use_pkcs11 = (pkcs11_library_path != null);
                if(use_pkcs11)
                {
                    if (!File.Exists(pkcs11_library_path))
                        throw new OptionException("PKCS11 library {0} does not exist", pkcs11_library_path);
                    if (password == null)
                        throw new OptionException("required parameter {0} missing", "password");
                } else if (!String.IsNullOrEmpty(thumbprint))
                {
                    if (password == null)
                        throw new OptionException("required parameter {0} missing", "password");
                }

                if (!File.Exists(infile))
                    throw new OptionException("input file {0} does not exist", infile);

                if (!String.IsNullOrEmpty(certfile) && !File.Exists(certfile))
                    throw new OptionException("certfile {0} does not exist", certfile);

                if (!string.IsNullOrEmpty(pageParam))
                {
                    if (pageParam.Equals("last", StringComparison.OrdinalIgnoreCase))
                        pageno = 0;
                    else if (!int.TryParse(pageParam, out pageno))
                        throw new OptionException("invalid page parameter {0}", pageParam);
                }

                if(certification_level > 3 || certification_level < 0)
                    throw new OptionException("invalid value for parameter {0}, must be 0-3", "certlevel");

                if((tsa_user != null && tsa_pass == null) || (tsa_user == null && tsa_pass != null))
                    throw new OptionException("To use TSA authentication both {0} must be specified", "tsauser and tsapass");

            }
            catch (OptionException e)
            {
                Console.Write("pdfsign: ");
                Console.WriteLine(e.Message, e.OptionName);
                Console.WriteLine("Try `pdfsign --help' for more information.");
                return (int)retval;
            }

            try
            {
                List<X509Certificate> extra_certs = new List<X509Certificate>();;
                X509Certificate signing_cert = null;
                IExternalSignature signature = null;

                if(use_pkcs11)
                {
                    retval = Retvals.ERR_TOKEN;
                    using (Pkcs11Explorer pkcs11Explorer = new Pkcs11Explorer(pkcs11_library_path))
                    {
                        // Find token to use
                        List<Token> tokens = pkcs11Explorer.GetTokens();
                        Token token_to_use = null;
                        Certificate pkcs11_certificate_to_use = null;
                        if(tokens.Count == 0)
                        {
                            throw new InvalidOperationException("No connected tokens could be found.");
                        }
                        else if(tokens.Count == 1 && token_serial == null)
                        {
                            token_to_use = tokens[0];
                            token_serial = tokens[0].SerialNumber;
                        } else if(token_serial != null)
                        {
                            foreach (Token token in tokens)
                            {
                                if(token.SerialNumber == token_serial)
                                { 
                                    token_to_use = token;
                                }
                            }
                        }
                        if(token_to_use != null)
                        {
                            Console.WriteLine("The following token will be used for signature:");
                            Console.WriteLine("  Manufacturer:       " + token_to_use.ManufacturerId);
                            Console.WriteLine("  Model:              " + token_to_use.Model);
                            Console.WriteLine("  Serial number:      " + token_to_use.SerialNumber);
                            Console.WriteLine("  Label:              " + token_to_use.Label);
                            Console.WriteLine();

                            // find certificate to use
                            // Get private keys and certificates stored in requested token
                            List<PrivateKey> privateKeys = null;
                            List<Certificate> pkcs11_certificates = null;
                            pkcs11Explorer.GetTokenObjects(token_to_use, true, password, out privateKeys, out pkcs11_certificates);

                            if(pkcs11_certificates.Count == 0)
                            {
                                throw new InvalidOperationException("No certificates found on selected token.");
                            }
                            else if(pkcs11_certificates.Count == 1 && cert_id == null) {
                                pkcs11_certificate_to_use = pkcs11_certificates[0];
                                cert_id = pkcs11_certificate_to_use.Id;
                            } else if(cert_id != null)
                            {
                                foreach (Certificate pkcs11_certificate in pkcs11_certificates)
                                {
                                    if(pkcs11_certificate.Id == cert_id)
                                    { 
                                        pkcs11_certificate_to_use = pkcs11_certificate;
                                    }
                                }
                            }
                            if(pkcs11_certificate_to_use != null)
                            {
                                Console.WriteLine("The following certificate will be used for signature:");
                                System.Security.Cryptography.X509Certificates.X509Certificate2 x509Cert = CertUtils.ToDotNetObject(pkcs11_certificate_to_use.Data);
                                Console.WriteLine("  ID (CKA_ID):        " + pkcs11_certificate_to_use.Id);
                                Console.WriteLine("  Label (CKA_LABEL):  " + pkcs11_certificate_to_use.Label);
                                Console.WriteLine("  Serial number:      " + x509Cert.SerialNumber);
                                Console.WriteLine("  Subject DN:         " + x509Cert.Subject);
                                Console.WriteLine("  Issuer DN:          " + x509Cert.Issuer);
                                Console.WriteLine("  Not before:         " + x509Cert.NotBefore);
                                Console.WriteLine("  Not after:          " + x509Cert.NotAfter);
                                Console.WriteLine();
                            } else
                            {
                                if (cert_id == null)
                                {
                                    Console.WriteLine("Multiple certificates found on token. Use -certid argument to specify which one to use.");
                                } else
                                {
                                    Console.WriteLine("Certificate with ID " + cert_id + " could not be found on token.");
                                }
                                Console.WriteLine("The following certificates were found on the token:");
                                int k = 1;
                                foreach (Certificate pkcs11_certificate in pkcs11_certificates)
                                {
                                    Console.WriteLine();
                                    Console.WriteLine("Certificate #" + k);

                                    System.Security.Cryptography.X509Certificates.X509Certificate2 x509Cert = CertUtils.ToDotNetObject(pkcs11_certificate.Data);

                                    Console.WriteLine("  ID (CKA_ID):        " + pkcs11_certificate.Id);
                                    Console.WriteLine("  Label (CKA_LABEL):  " + pkcs11_certificate.Label);
                                    Console.WriteLine("  Serial number:      " + x509Cert.SerialNumber);
                                    Console.WriteLine("  Subject DN:         " + x509Cert.Subject);
                                    Console.WriteLine("  Issuer DN:          " + x509Cert.Issuer);
                                    Console.WriteLine("  Not before:         " + x509Cert.NotBefore);
                                    Console.WriteLine("  Not after:          " + x509Cert.NotAfter);
                                    k++;
                                }
                                Console.WriteLine();
                                throw new InvalidOperationException("Certificate not found on token.");
                            }
                        } else
                        {
                            if(token_serial == null)
                            {
                                Console.WriteLine("Multiple tokens found. Use -tokenserial argument to specify which one to use.");
                            } else {
                                Console.WriteLine("Could not find token with serial " + token_serial);
                            }
                            Console.WriteLine("Listing available tokens");
                            int j = 1;
                            foreach (Token token in tokens)
                            {
                                Console.WriteLine();
                                Console.WriteLine("Token no." + j);
                                Console.WriteLine("  Manufacturer:       " + token.ManufacturerId);
                                Console.WriteLine("  Model:              " + token.Model);
                                Console.WriteLine("  Serial number:      " + token.SerialNumber);
                                Console.WriteLine("  Label:              " + token.Label);
                                j++;
                            }
                            throw new InvalidOperationException("Token not found.");
                        }
                        // Use SHA256 as default hashing algorithm
                        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;
                        Pkcs11RsaSignature pkcs11_signature = new Pkcs11RsaSignature(pkcs11_library_path, token_serial, null, password, null, cert_id, hashAlgorithm);
                        signing_cert = CertUtils.ToBouncyCastleObject(pkcs11_signature.GetSigningCertificate());
                        foreach(byte[] other_cert in pkcs11_signature.GetAllCertificates())
                        {
                            extra_certs.Add(CertUtils.ToBouncyCastleObject(other_cert));
                        }
                        signature = pkcs11_signature;
                    }
                } else if(!String.IsNullOrEmpty(thumbprint) || !String.IsNullOrEmpty(certfile)) // use certificate file
                {
                    retval = Retvals.ERR_CERT; // Error processing certificate file
                    Stream fs = null; 
                    if (!String.IsNullOrEmpty(thumbprint))
                    {
                        System.Security.Cryptography.X509Certificates.X509Certificate2 cer = null;
                        System.Security.Cryptography.X509Certificates.StoreLocation certStoreLocation = System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine;
                        if (store.Equals("CurrentUser", StringComparison.OrdinalIgnoreCase))
                            certStoreLocation = System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser;
                        System.Security.Cryptography.X509Certificates.X509Store certStore = 
                            new System.Security.Cryptography.X509Certificates.X509Store(certStoreLocation);
                        certStore.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);
                        System.Security.Cryptography.X509Certificates.X509Certificate2Collection certs =
                            certStore.Certificates.Find(System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint, thumbprint, false);
                        if (certs.Count > 0)
                        {
                            cer = certs[0];
                        } else
                        {
                            throw new InvalidOperationException("Certificate with specified thumbprint not found");
                        }
                        System.Security.Cryptography.X509Certificates.X509Certificate2Collection certCol = new System.Security.Cryptography.X509Certificates.X509Certificate2Collection();
                        System.Security.Cryptography.X509Certificates.X509Chain x509chain = new System.Security.Cryptography.X509Certificates.X509Chain();
                        x509chain.ChainPolicy.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
                        x509chain.Build(cer);
                        for (int chainIDX = 0; chainIDX < x509chain.ChainElements.Count; chainIDX++)
                            certCol.Add(x509chain.ChainElements[chainIDX].Certificate);
                        password = "12345";
                        byte[] pkcs12 = certCol.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pkcs12, password);
                        fs = new MemoryStream(pkcs12);
                        fs.Seek(0, SeekOrigin.Begin);
                    }
                    else
                    {
                        fs = new FileStream(certfile, FileMode.Open, FileAccess.Read);
                    }
                    Pkcs12Store ks = new Pkcs12Store(fs, password.ToCharArray());
                    string alias = null;
                    foreach (string al in ks.Aliases)
                    {
                        if (ks.IsKeyEntry(al) && ks.GetKey(al).Key.IsPrivate)
                        {
                            alias = al;
                            break;
                        }
                    }
                    fs.Close();

                    retval = Retvals.ERR_KEY; // Error extracting secret key
                    ICipherParameters pk = ks.GetKey(alias).Key;

                    retval = Retvals.ERR_CHAIN; // Error extracting certificate chain
                    signing_cert = ks.GetCertificate(alias).Certificate;
                    X509CertificateEntry[] chainEntries = ks.GetCertificateChain(alias);
                    foreach(X509CertificateEntry entry in chainEntries)
                    {
                        extra_certs.Add(entry.Certificate);
                    }
                    signature = new PrivateKeySignature(pk, "SHA-256");
                }

                retval = Retvals.ERR_INPUT; // Error processing input file
                PdfReader reader;
                if (string.IsNullOrEmpty(backpage))
                {
                    reader = new PdfReader(infile);
                } else
                {
                    MemoryStream tmpOut = new MemoryStream();
                    Document document = new Document();
                    PdfCopy copy = new PdfSmartCopy(document, tmpOut);
                    document.Open();
                    using (var r = new PdfReader(infile))
                        copy.AddDocument(r);
                    using (var r = new PdfReader(backpage))
                        copy.AddDocument(r);
                    document.Close();
                    reader = new PdfReader(tmpOut.ToArray());
                }

                retval = Retvals.ERR_OUTPUT; // Error opening output file
                FileStream fout = new FileStream(outfile, FileMode.Create, FileAccess.Write);

                retval = Retvals.ERR_SIGN; // Error generating signature
                PdfStamper stp = PdfStamper.CreateSignature(reader, fout, '\0', null, multi_signature);
                PdfSignatureAppearance sap = stp.SignatureAppearance;

                sap.Reason = reason;
                sap.Contact = contact;
                sap.Location = location;
                sap.Acro6Layers = !show_validity;
                sap.CertificationLevel = certification_level;

                TSAClientBouncyCastle tsaClient = null;
                if (!string.IsNullOrEmpty(tsa_url))
                {
                    if(tsa_user != null && tsa_pass != null)
                        tsaClient = new TSAClientBouncyCastle(tsa_url, tsa_user, tsa_pass);
                    else
                        tsaClient = new TSAClientBouncyCastle(tsa_url);
                }

                // when using visible signatures: find an unused field name for the signature
                if (show_signature)
                {
                    string basename = "Signature";
                    if(timestamp_only)
                        basename = "Timestamp";
                    AcroFields form = reader.AcroFields;
                    int cnt = -1;
                    string name;
                    do
                    {
                        cnt++;
                        name = basename;
                        if (cnt != 0)
                            name = name + cnt;

                    } while (form.GetField(name) != null);
                    int xoff = (cnt % cols) * (width + hsep) + hoffset;
                    int yoff = cnt / cols * (height + vsep) + voffset;
                    if (pageno == 0 || pageno > reader.NumberOfPages)
                        pageno = reader.NumberOfPages;

                    if (!String.IsNullOrEmpty(template))
                    {
                        template = template.Replace("\\n", "\n");
                        string subject = null;
                        if(signing_cert!=null)
                            subject = signing_cert.SubjectDN.GetValueList(new Org.BouncyCastle.Asn1.DerObjectIdentifier("2.5.4.3"))[0].ToString();
                        string date = sap.SignDate.ToString(dateformat);
                        template = template.Replace("[name]", subject);
                        template = template.Replace("[date]", date);
                        sap.Layer2Text = template;
                    }

                    sap.SetVisibleSignature(new Rectangle(xoff, yoff, xoff + width, yoff + height), pageno, name);
                }

                if(use_ltv) {
                    AdobeLtvEnabling adobeLtvEnabling = new AdobeLtvEnabling(stp);
                    OcspVerifier verifier = new OcspVerifier(null, null);
                    IOcspClient oscpClient = new OcspClientBouncyCastle(verifier);
                    X509Certificate tsaCert = adobeLtvEnabling.addLtvForTsa(tsaClient, oscpClient);
                    if(!timestamp_only) {
                        extra_certs.Add(signing_cert);
                        AdobeLtvEnabling.extraCertificates = extra_certs;
                        ICrlClient crlClient = new CrlClientOnline(extra_certs);
                        adobeLtvEnabling.addLtvForChain(signing_cert, oscpClient, crlClient, PdfName.A);
                    } else
                    {
                        sap.Certificate = tsaCert;
                    }
                    adobeLtvEnabling.outputDss();
                }

                if(timestamp_only) {
                    LtvTimestampHidden.Timestamp(sap, tsaClient, sap.FieldName);
                } else
                {
                    MakeSignature.SignDetached(sap,
                                               signature,
                                               new X509Certificate[]{ signing_cert },
                                               null,
                                               null,
                                               tsaClient,
                                               0,
                                               CryptoStandard.CADES);
                }

                stp.Close();
            }
            catch (Exception e)
            {
                Console.Write("pdfsign: ");
                Console.WriteLine(e.Message);
                Console.WriteLine();
                Console.WriteLine(e.StackTrace);
                return (int)retval;
            }

            // looks like it worked, return success
            Console.Write("pdf signed.");
            return (int)Retvals.SUCCESS;
        }
    }
}
