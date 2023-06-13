
General info: 
Compiler: EP:Microsoft Visual C/C++(2008-2010)[EXE32] 
Linker: Microsoft Linker(10.0)[GUI32,signed] 
Certificate: WinAuth(2.0)[PKCS #7]


| Type   | Description                                                      | File        |
| ------ | ---------------------------------------------------------------- | ----------- |
| SHA256 | d4492a9eb36f87a9b3156b59052ebaf10e264d5d1ce4c015a6b0d205614e58e3 | Nefilim.exe |


## Getting the ransom note

First creates a RSA hash context using `CryptAcquireContextA(hProv, 0, 0, PROV_RSA_FULL, 0xF0000000)`, which will create a HCRYPTPROV* phProv that will be used as context by the subsequent functions 

Them uses `CryptCreateHash(&hProv, CALG_SHA,0 ,0, HCRYPTHASH* phHash)` to create a SHA1 key which copies a handle to the specified hash object phHash.

After that, Nefilim derivate a RC4 key based on the created SHA1 hash, with `CryptDeriveKey(phProv, CALG_RC4, phHash, 1, &phKey)`

After generate the RC4 key, based on the string  
`ya chubstvuu bol' gde-to v grude, i moi rani v serdce ne zalechit'`

the malware uses the CryptDecrypt function to generate his ransom note with the base64 string and the RC4 generated key 

```
base64 ->
P28bYetqAjMJwFdCu5KwgN5PGwkVckpRko+dpaPjLO7ofFiQDbKw8ovNbVTREf1xBQ6glzyU76V79uTCpaWeKoTIK27f4cF8GbrTFtiCBEPGFKlFUa9xOFxA/8iU3vp7QOYlJc6pPmGT0Z/MFnQhE0CqYav+ZfHo60djvhkjRBtoPLUcpUQ5jkOczEZPbghBDMjFVM/YFb49N687qDVvrBkiWsz2ehCWS0SMxVMJi4dpMwTc3FybPQPE73FBRFUS/aAHGjcQuSxMlzvAB7CqiEVjpFUodQwjRe7vkyt30HhFnEZmjqwbGTJea2tQ4jZ6AxIekd1brjxQuiQm+gmfc8Ic8zUBwuJgqvtZ0Nq1bPcEjakY2CI5cc+S4LZUTPU6njhVyVHifOH/tSn9IrD9jX6AODDD2jrQx4iVeZ4MnziKWlmcp9/WEgfmLGhGd0kAlpyXbJgBvjIAtvkdiSfyXnWtQSpqO0aLHIoBU+zfOTAOrSoFUEIRoEGYgV
```

Which will result in a file named `NEFILIM-DECRYPT.txt` with the message: 
``` 
"All of your files have been encrypted with military grade algorithms.\r\n\r\nWe ensure that the only way to retrieve your data is with our software.\r\nWe will make sure you retrieve your data swiftly and securely when our demands are met.\r\nRestoration of your data requires a private key which only we possess.\r\nA large amount of your private files have been extracted and is kept in a secure location.\r\nIf you do not contact us in seven working days of the breach we will start leaking the data.\r\n"
```

### Encrypting files
First of all Nefilim uses CryptImportKey to import an RSA key, after that it generate a pseudo random 128bits number to encypt with this RSA-2048 key two times, ending up with the following fluxogram:
`a = rsa_encrypt(gen_128bits_a)`
`b = rsa_encrypt(gen_128bits_b)`

write(encrypted_file, a)
Parses the file from the beginning into a function with looks like func(file_content, file_size, b) 

>Todo: get the function source code

function offset -> Nefilim.40128F 

"Working in progresss"

# Yara rule:
```c++
import "pe"

  // There is still much things to do with this rule

rule Nefilim {
	meta:
		author = "@Josu3_"
    strings:

        $r_note = "NEFILIM-DECRYPT.txt" wide

        $rc4_key= "P28bYetqAjMJwFdCu5KwgN5PGwkVckpRko+dpaPjLO7ofFiQDbKw8ovNbVTREf1xBQ6glzyU76V79uTCpaWeKoTIK27f4cF8GbrTFtiCBEPGFKlFUa9xOFxA/8iU3vp7QOYlJc6pPmGT0Z/MFnQhE0CqYav+ZfHo60djvhkjRBtoPLUcpUQ5jkOczEZPbghBDMjFVM/YFb49N687qDVvrBkiWsz2ehCWS0SMxVMJi4dpMwTc3FybPQPE73FBRFUS/aAHGjcQuSxMlzvAB7CqiEVjpFUodQwjRe7vkyt30HhFnEZmjqwbGTJea2tQ4jZ6AxIekd1brjxQuiQm+gmfc8Ic8zUBwuJgqvtZ0Nq1bPcEjakY2CI5cc+S4LZUTPU6njhVyVHifOH/tSn9IrD9jX6AODDD2jrQx4iVeZ4MnziKWlmcp9/WEgfmLGhGd0kAlpyXbJgBvjIAtvkdiSfyXnWtQSpqO0aLHIoBU+zfOTAOrSoFUEIRoEGYgV"

        $ystring = "ya chubstvuu bol' gde-to v grude, i moi rani v serdce ne zalechit'"

  

    condition:

        pe.imports("ADVAPI32.DLL", "CryptHashData") and

        pe.imports("ADVAPI32.DLL", "CryptDeriveKey") and

        pe.imports("ADVAPI32.DLL", "CryptEncrypt") and

        pe.imports("ADVAPI32.DLL", "CryptDecrypt") and

        pe.imports("ADVAPI32.DLL", "CryptImportKey") and

        filesize < 100000 and all of them

}
```
