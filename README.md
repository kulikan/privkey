# privkey
Convert CryptoPro container to OpenSSL container

You need to have Strawberry perl and Visual Studio installed

### Contents

1) Download OpenSSL https://github.com/openssl/openssl/releases/tag/OpenSSL_1_1_1a 
and unpack it to dir "openssl-OpenSSL_1_1_1a"

2) Compile OpenSSL via bat-file:

~~~
call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat"
path=C:\Strawberry\perl\bin;C:\Users\D36B~1\AppData\Local\bin\NASM;%path%
perl Configure VC-WIN32 no-hw no-asm
nmake
~~~

3) Download gost https://github.com/gost-engine/engine 
and unpack it to dir "engine-master"

4) Use this bat-file to compile privkey.exe :

~~~
call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat"
cl -DL_ENDIAN -Iopenssl-OpenSSL_1_1_1a\ms -Iopenssl-OpenSSL_1_1_1a\include -Iengine-master ^
   privkey.c ^
   engine-master\gost89.c engine-master\gosthash.c engine-master\gost_ameth.c ^
   engine-master\gost_crypt.c engine-master\gost_ctl.c engine-master\gost_asn1.c ^
   engine-master\gost_ec_sign.c engine-master\e_gost_err.c engine-master\gost_params.c ^
   engine-master\gosthash2012.c libcrypto.lib
~~~

5) Convert CryptoPro container to OpenSSL container run:
~~~
privkey.exe a:\lp-9a0fe.000 > private.key
~~~

6) Sign file using signer.cer and private.key:
~~~
openssl cms -sign -inkey private.key -in file.txt -CAfile CA.cer -signer signer.cer -engine gost -out file.txt.sgn -outform DER -noattr -binary
~~~

7) Check sign file:
~~~
openssl cms -verify -content file.txt -in file.txt.sgn -CAfile CA.cer -signer signer.cer -engine gost -inform DER -noattr -binary
~~~
