/**************************************************************************************************************************************************************
 * FILE NAME		:	checksum.c
 * DESCRIPTION		:	computes the md5 for key
 * RETURN VALUE	:	        int
 ****************************************************************************************************************************************************************/
/**************************************************************************************************************************************************************
 * 			     HEADER FILES and MACROS
 ****************************************************************************************************************************************************************/
#include "wrapfs.h"

int checksum(char *user_key, char *chksum)
{
    char *buf = NULL,*MD5_digest = NULL;
    int err,i,ret,len = 0;;
   // int len;
   // int ret = 0;
    char *digest = NULL;
    const int KEY_LENGTH = 33;
    struct hash_desc desc;
    struct crypto_hash *tfm;
    struct scatterlist sg;
  //  mm_segment_t oldfs;
    len = strlen(user_key);

    buf = kmalloc(len,GFP_KERNEL);
    if(buf == NULL)
    {
	printk("ERROR in memory allocation\n");
	err = -ENOMEM;
	goto bin;
    }
    memset(buf, 0 , len);

    MD5_digest = kmalloc(KEY_LENGTH, GFP_KERNEL);
    if(MD5_digest == NULL)
    {
	printk("ERROR in memory allocation\n");
	err = -ENOMEM;
	goto bin;	
    }
    memset(MD5_digest,0,(2*MD5_SIGNATURE_SIZE)+1);

    digest = kmalloc((MD5_SIGNATURE_SIZE+1) * sizeof(char), GFP_KERNEL);
    if(digest == NULL)
    {
	printk("ERROR in memory allocation\n");
	err = -ENOMEM;
	goto bin;
    }
    memset(digest, 0 , MD5_SIGNATURE_SIZE+1);	

    strncpy(buf,user_key,len);
    tfm = crypto_alloc_hash("md5",0,CRYPTO_ALG_ASYNC);
    if (IS_ERR(tfm))
    {
	printk("Unable to allocate struct srypto_hash\n");
    }

    desc.tfm = tfm;
    desc.flags = 0;

    ret = crypto_hash_init(&desc);
    if(ret<0)
    {
	printk("crypto_hash_init() failed\n");
	crypto_free_hash(tfm);
    }
   // oldfs = get_fs();
   // set_fs(KERNEL_DS);
    /* Reading the file chunk by chunk. Here we are reading the file = PAGE_SIZE which is equal to 4096 */

    sg_init_one(&sg,(void *) buf,len);
    err = crypto_hash_update(&desc,&sg,len);
    if(err<0)
    {
	printk("crypto_hash_update() failed for id\n");
	crypto_free_hash(tfm);
	err = -EINVAL;
	goto bin;
    }


   // set_fs(oldfs);
    err = crypto_hash_final(&desc,digest);
    if (err<0)
    {
	printk("crypto_hash_final() failed for sever digest");
	crypto_free_hash(tfm);
	err = -EINVAL;
	goto bin;
    }
    for(i = 0; i<16; i++)
    {
	sprintf((MD5_digest + i*2),"%02x",digest[i] & 0xFF);
    }	
    memcpy(chksum,MD5_digest,KEY_LENGTH);
    /*	len1 = strlen(chksum);*/

bin:
    if(buf)
	kfree(buf);
    if(MD5_digest)
	kfree(MD5_digest);
    if(digest)
	kfree(digest);
    return err;
}



