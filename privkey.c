#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include "gost_lcl.h"

#include "gosthash2012.h"
#include "applink.c"

//remove the function if link failed
void inc_counter(unsigned char *counter, size_t counter_bytes)
{
    unsigned char c;
    unsigned int n = counter_bytes;

    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c)
            return;
    } while (n);
}

/* Convert little-endian byte array into bignum */
BIGNUM *reverse_bn(char *b, int len, BN_CTX *ctx)
{
	BIGNUM *res;
	char buf[64];
	BUF_reverse(buf, b, len);
	res = BN_bin2bn(buf, len, BN_CTX_get(ctx));
	OPENSSL_cleanse(buf, sizeof(buf));
	return res;
}

void xor_material(char *buf36, char *buf5C, char *src, int len_material)
{
	int i;
	for(i = 0; i < len_material; i++)
	{
		buf36[i] = src[i] ^ 0x36;
		buf5C[i] = src[i] ^ 0x5C;
	}
}

int make_pwd_key64(char *result_key, char *start12, int start12_len, char *passw)
{
	int result;
	int i;
	char pincode4[1024];
	int pin_len;
	char current[64];
	char material36[64];
	char material5C[64];
	char hash_result[32];
	gost2012_hash_ctx ctx;

	memset(pincode4, 0, sizeof(pincode4));
	pin_len = strlen(passw);
	if (pin_len*4 > sizeof(pincode4)) {	result = 1;	goto err; }
	for(i = 0; i < pin_len; i++)
		pincode4[i*4] = passw[i];

	init_gost2012_hash_ctx(&ctx, 256);
	gost2012_hash_block(&ctx, start12, start12_len);
	if (pin_len) 
		gost2012_hash_block(&ctx, pincode4, pin_len * 4);
	gost2012_finish_hash(&ctx, hash_result);

	memcpy(current, (char*)"DENEFH028.760246785.IUEFHWUIO.EF", 32);
    memset(current+32, 0, 32);

	for(i = 0; i < (pin_len?2000:2); i++)
	{
		xor_material(material36, material5C, current, 64);
		init_gost2012_hash_ctx(&ctx, 256);
		gost2012_hash_block(&ctx, material36, 64);
		gost2012_hash_block(&ctx, hash_result, 32);
		gost2012_hash_block(&ctx, material5C, 64);
		gost2012_hash_block(&ctx, hash_result, 32);
		gost2012_finish_hash(&ctx, current);
	}

	xor_material(material36, material5C, current, 64);

	init_gost2012_hash_ctx(&ctx, 256);
	gost2012_hash_block(&ctx, material36, 32);
	gost2012_hash_block(&ctx, start12, start12_len);
	gost2012_hash_block(&ctx, material5C, 32);
	if (pin_len) 
		gost2012_hash_block(&ctx, pincode4, pin_len * 4);
	gost2012_finish_hash(&ctx, current);

	init_gost2012_hash_ctx(&ctx, 256);
	gost2012_hash_block(&ctx, current, 32);
	gost2012_finish_hash(&ctx, result_key);

	result = 0; //ok
err:
	return result;
}

int make_pwd_key(char *result_key, char *start12, int start12_len, char *passw)
{
	int result;
	int i;
	char pincode4[1024];
	int pin_len;
	char current[32];
	char material36[32];
	char material5C[32];
	char hash_result[32];
	gost_hash_ctx ctx;
	init_gost_hash_ctx(&ctx, &GostR3411_94_CryptoProParamSet);
	memset(pincode4, 0, sizeof(pincode4));
	pin_len = strlen(passw);
	if (pin_len*4 > sizeof(pincode4)) {	result = 1;	goto err; }
	for(i = 0; i < pin_len; i++)
		pincode4[i*4] = passw[i];

	start_hash(&ctx);
	hash_block(&ctx, start12, start12_len);
	if (pin_len) 
		hash_block(&ctx, pincode4, pin_len * 4);
	finish_hash(&ctx, hash_result);

	memcpy(current, (char*)"DENEFH028.760246785.IUEFHWUIO.EF", 32);

	for(i = 0; i < (pin_len?2000:2); i++)
	{
		xor_material(material36, material5C, current, 32);
		start_hash(&ctx);
		hash_block(&ctx, material36, 32);
		hash_block(&ctx, hash_result, 32);
		hash_block(&ctx, material5C, 32);
		hash_block(&ctx, hash_result, 32);
		finish_hash(&ctx, current);
	}

	xor_material(material36, material5C, current, 32);

	start_hash(&ctx);
	hash_block(&ctx, material36, 32);
	hash_block(&ctx, start12, start12_len);
	hash_block(&ctx, material5C, 32);
	if (pin_len) 
		hash_block(&ctx, pincode4, pin_len * 4);
	finish_hash(&ctx, current);

	start_hash(&ctx);
	hash_block(&ctx, current, 32);
	finish_hash(&ctx, result_key);

	result = 0; //ok
err:
	return result;
}

extern gost_subst_block Gost28147_CryptoProParamSetA;
extern gost_subst_block Gost28147_TC26ParamSetZ;
BIGNUM *decode_primary_key(char *pwd_key, char *primary_key, BN_CTX *bn_ctx, int len_material, int flag_Z)
{
	BIGNUM *res;
	char buf[64];
	gost_ctx ctx;
	if (flag_Z==0)
		gost_init(&ctx, &Gost28147_CryptoProParamSetA);
	else
		gost_init(&ctx, &Gost28147_TC26ParamSetZ);
	gost_key(&ctx, pwd_key);
	gost_dec(&ctx, primary_key, buf, len_material/8);
	res = reverse_bn(buf, len_material, bn_ctx);
	OPENSSL_cleanse(buf, sizeof(buf));
	return res;
}

BIGNUM *remove_mask_and_check_public(unsigned char *oid_param_set8, BIGNUM *key_with_mask, BIGNUM *mask, char *public8, BN_CTX *ctx)
{
	int result;
	EC_KEY *eckey = NULL;
	const EC_POINT *pubkey;
	const EC_GROUP *group;
	BIGNUM *X, *Y, *order, *raw_secret, *mask_inv;
	char outbuf[64], public_X[64];
	ASN1_OBJECT *obj;
	int nid;

	order = BN_CTX_get(ctx);
	mask_inv = BN_CTX_get(ctx);
	raw_secret = BN_CTX_get(ctx);
	X = BN_CTX_get(ctx);
	Y = BN_CTX_get(ctx);
	if (!order || !mask_inv || !raw_secret || !X || !Y) { result = 1; goto err; }

	obj = ASN1_OBJECT_create(0, oid_param_set8+1, *oid_param_set8, NULL, NULL);
	nid = OBJ_obj2nid(obj);
	ASN1_OBJECT_free(obj);

	if (!(eckey = EC_KEY_new())) { result = 1; goto err; }
	if (!fill_GOST_EC_params(eckey, nid)) { result = 1; goto err; }
	if (!(group = EC_KEY_get0_group(eckey))) { result = 1; goto err; }
	if (!EC_GROUP_get_order(group, order, ctx)) { result = 1; goto err; }
    if (!BN_is_word(EC_GROUP_get0_cofactor(group), 1)) BN_rshift(order, order, 2); //get q from m
	if (!BN_mod_inverse(mask_inv, mask, order, ctx)) { result = 1; goto err; }
	if (!BN_mod_mul(raw_secret, key_with_mask, mask_inv, order, ctx)) { result = 1; goto err; }

	if (!EC_KEY_set_private_key(eckey, raw_secret)) { result = 1; goto err; }
	if (!gost_ec_compute_public(eckey)) { result = 1; goto err; }
	if (!(pubkey = EC_KEY_get0_public_key(eckey))) { result = 1; goto err; }
	if (!EC_POINT_get_affine_coordinates_GFp(group, pubkey, X, Y, ctx)) { result = 1; goto err; }

	store_bignum(X, outbuf, sizeof(outbuf));
	BUF_reverse(public_X, outbuf, sizeof(outbuf));
	if (memcmp(public_X, public8, 8) != 0) { result = 1; goto err; }

	result = 0; //ok
err:
	if (eckey) EC_KEY_free(eckey);
	if (result == 0) return raw_secret;
	return NULL;
}

int file_length(char *fname)
{
	int len;
	FILE *f = fopen(fname, "rb");
	if (f == NULL) return -1;
	fseek(f, 0, SEEK_END);
	len = ftell(f);
	fclose(f);
	return len;
}

int read_file(char *fname, int start_pos, char *buf, int len)
{
	int read_len;
	FILE *f = fopen(fname, "rb");
	if (f == NULL) return 1;
	if (start_pos) fseek(f, start_pos, SEEK_SET);
	read_len = fread(buf, 1, len, f);
	fclose(f);
	if (read_len != len) return 1;
	return 0; //ok
}

#define OID_LIST 14
static unsigned char oid_list[OID_LIST][35] = {
	{0x30,0x21,6,8,0x2a,0x85,3,7,1,1,1,1,0x30,0x15,6,9,0x2a,0x85,3,7,1,2,1,1,1,6,8,0x2a,0x85,3,7,1,1,2,2},
    {0x30,0x1c,6,6,0x2a,0x85,3,2,2,0x13,0x30,0x12,6,7,0x2a,0x85,3,2,2,0x23,1,6,7,0x2a,0x85,3,2,2,0x1e,1},
    {0x30,0x1c,6,6,0x2a,0x85,3,2,2,0x13,0x30,0x12,6,7,0x2a,0x85,3,2,2,0x23,2,6,7,0x2a,0x85,3,2,2,0x1e,1},
    {0x30,0x1c,6,6,0x2a,0x85,3,2,2,0x13,0x30,0x12,6,7,0x2a,0x85,3,2,2,0x23,3,6,7,0x2a,0x85,3,2,2,0x1e,1},
    {0x30,0x1c,6,6,0x2a,0x85,3,2,2,0x13,0x30,0x12,6,7,0x2a,0x85,3,2,2,0x24,0,6,7,0x2a,0x85,3,2,2,0x1e,1},
    {0x30,0x1c,6,6,0x2a,0x85,3,2,2,0x13,0x30,0x12,6,7,0x2a,0x85,3,2,2,0x24,1,6,7,0x2a,0x85,3,2,2,0x1e,1},
    {0x30,0x1f,6,8,0x2a,0x85,3,7,1,1,1,1,0x30,0x13,6,7,0x2a,0x85,3,2,2,0x23,1,6,8,0x2a,0x85,3,7,1,1,2,2},
    {0x30,0x1f,6,8,0x2a,0x85,3,7,1,1,1,1,0x30,0x13,6,7,0x2a,0x85,3,2,2,0x23,2,6,8,0x2a,0x85,3,7,1,1,2,2},
    {0x30,0x1f,6,8,0x2a,0x85,3,7,1,1,1,1,0x30,0x13,6,7,0x2a,0x85,3,2,2,0x23,3,6,8,0x2a,0x85,3,7,1,1,2,2},
    {0x30,0x1f,6,8,0x2a,0x85,3,7,1,1,1,1,0x30,0x13,6,7,0x2a,0x85,3,2,2,0x24,0,6,8,0x2a,0x85,3,7,1,1,2,2},
    {0x30,0x1f,6,8,0x2a,0x85,3,7,1,1,1,1,0x30,0x13,6,7,0x2a,0x85,3,2,2,0x24,1,6,8,0x2a,0x85,3,7,1,1,2,2},
    {0x30,0x21,6,8,0x2a,0x85,3,7,1,1,1,2,0x30,0x15,6,9,0x2a,0x85,3,7,1,2,1,2,1,6,8,0x2a,0x85,3,7,1,1,2,3},
    {0x30,0x21,6,8,0x2a,0x85,3,7,1,1,1,2,0x30,0x15,6,9,0x2a,0x85,3,7,1,2,1,2,2,6,8,0x2a,0x85,3,7,1,1,2,3},
    {0x30,0x21,6,8,0x2a,0x85,3,7,1,1,1,2,0x30,0x15,6,9,0x2a,0x85,3,7,1,2,1,2,3,6,8,0x2a,0x85,3,7,1,1,2,3}
};
static int flag_z_list[OID_LIST] = {1,0,0,0,0,0,1,1,1,1,1,1,1,1};
static int len_material_list[OID_LIST] = {32,32,32,32,32,32,32,32,32,32,32,64,64,64};
static int len_material_pwd_list[OID_LIST] = {64,32,32,32,32,32,64,64,64,64,64,64,64,64};

#define OID_LEN 1
int check_oid(unsigned char *str1, int str1_len, unsigned char *str2)
{
	int i,j;
	int str2_len = str2[OID_LEN]+2; //oid len
	for(i=0;i<str1_len-str2_len;i++)
	{
		for(j=0;;j++)
		{
			if (j==str2_len) return 0; //ok
			if (str1[i+j]!=str2[j]) break;
		}
	}
	return 1; //not found
}

#define MAX_HEADER 20000
int read_container(char *fpath, int flag2, char *salt12, char *primary_key, char *masks_key, char *public8, int *param_set)
{
	int result;
	char primary_path[1024+30];
	char masks_path[1024+30];
	char header_path[1024+30];
	char header_buf[MAX_HEADER];
	int header_len;
	int i, len, pos, size_hdr;

	if (strlen(fpath)>1024) { result = 1; goto err; }

	sprintf(header_path, "%s/header.key", fpath);
	if (flag2 == 0)
	{
		sprintf(primary_path, "%s/primary.key", fpath);
		sprintf(masks_path, "%s/masks.key", fpath);
	}
	else
	{
		sprintf(primary_path, "%s/primary2.key", fpath);
		sprintf(masks_path, "%s/masks2.key", fpath);
	}
	header_len = file_length(header_path);
	if (header_len < 0x42 || header_len > MAX_HEADER) { result = 1; goto err; }
	if (read_file(header_path, 0, header_buf, header_len)) { result = 1; goto err; }
//------------- get param set ---------------------------
	for(i=0;i<OID_LIST;i++)	if (check_oid(header_buf, header_len, oid_list[i])==0) break;
	if (i==OID_LIST) { result = 2; goto err; }; //not found
	*param_set = i; //param set found
	if (read_file(primary_path, 4, primary_key, len_material_list[i])) { result = 1; goto err; }
	if (read_file(masks_path, 4, masks_key, len_material_list[i])) { result = 1; goto err; }
	if (read_file(masks_path, 0x26+len_material_list[i]-32, salt12, 12)) { result = 1; goto err; }
//------------------ get public8 -----------------------
	pos = header_len - 51;
	if (memcmp(header_buf+pos, "\x8a\x8", 2) == 0)
	{
		memcpy(public8,header_buf+pos+2,8);
		result = 0; //ok
	}
	else
		result = 2; //not found
err:
	OPENSSL_cleanse(header_buf, sizeof(header_buf));
	return result;
}

int main(int argc, char **argv)
{
	int result;
	char *container_path;
	char *passw;
	char salt12[12];
	char primary_key[64];
	char masks_key[64];
	char public8[8];
	unsigned char *oid_publ_key;
	BN_CTX *ctx;
	BIGNUM *key_with_mask;
	BIGNUM *mask;
	BIGNUM *raw_key;
	char pwd_key[32];
	char outbuf[64];
	int param_set;
	int len_material;
	char asn1_private_key[5+50+5+50];
	int len_private_key;

	ctx = BN_CTX_new();

	if (argc == 2)
	{
		container_path = argv[1];
		passw = "";
	}
	else
	if (argc == 3)
	{
		container_path = argv[1];
		passw = argv[2];
	}
	else
	{
		printf("privkey cpro_container_path [passw]\n");
		result = 1;
		goto err;
	}

	if (read_container(container_path, 0, salt12, primary_key, masks_key, public8, &param_set) != 0 &&
		read_container(container_path, 1, salt12, primary_key, masks_key, public8, &param_set) != 0)
	{
		printf("can not read container from %s\n", container_path);
		result = 2;
		goto err;
	}
	len_material = len_material_list[param_set];
	oid_publ_key = oid_list[param_set]+3;
	oid_publ_key += oid_publ_key[0]+4;

	if (len_material_pwd_list[param_set]==64)
		make_pwd_key64(pwd_key, salt12, 12, passw);
	else
		make_pwd_key(pwd_key, salt12, 12, passw);
	key_with_mask = decode_primary_key(pwd_key, primary_key, ctx, len_material, flag_z_list[param_set]);
	OPENSSL_cleanse(pwd_key, sizeof(pwd_key));
	mask = reverse_bn(masks_key, len_material, ctx);
	raw_key = remove_mask_and_check_public(oid_publ_key, key_with_mask, mask, public8, ctx);

	if (raw_key)
	{
		BIO *bio;
		int flag_pad=0;
		int len_oid;
		store_bignum(raw_key, outbuf, len_material);
		if (outbuf[0]&0x80)	flag_pad=1;
		len_private_key=0;
		asn1_private_key[len_private_key++]=0x30;
		asn1_private_key[len_private_key++]=0x46;
		asn1_private_key[len_private_key++]=2;
		asn1_private_key[len_private_key++]=1;
		asn1_private_key[len_private_key++]=0;
		len_oid=oid_list[param_set][OID_LEN]+2;
		memcpy(asn1_private_key+len_private_key, oid_list[param_set], len_oid); len_private_key+=len_oid;
		asn1_private_key[len_private_key++]=0x4;
		asn1_private_key[len_private_key++]=len_material+flag_pad+2;
		asn1_private_key[len_private_key++]=0x2;
		asn1_private_key[len_private_key++]=len_material+flag_pad;
		if (flag_pad) asn1_private_key[len_private_key++]=0;
		memcpy(asn1_private_key+len_private_key, outbuf, len_material); len_private_key+=len_material;
		asn1_private_key[1]=len_private_key-2;
		//bio = BIO_new_file("private.key", "w");
		bio = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
		PEM_write_bio(bio, "PRIVATE KEY", "", asn1_private_key, len_private_key);
		BIO_free(bio);
		OPENSSL_cleanse(outbuf, sizeof(outbuf));
		OPENSSL_cleanse(asn1_private_key, sizeof(asn1_private_key));
		result = 0; //ok
	}
	else
	{
		printf("Error check public key\n");
		result = 3;
	}

err:
	BN_CTX_free(ctx);
	OPENSSL_cleanse(salt12, sizeof(salt12));
	OPENSSL_cleanse(primary_key, sizeof(primary_key));
	OPENSSL_cleanse(masks_key, sizeof(masks_key));
	return result;
}
