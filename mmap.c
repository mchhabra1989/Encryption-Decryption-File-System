#include "wrapfs.h"
int wrapfs_encrypt(char *src, int src_len, char *dst, int dst_len, char *key, int key_len);
#define MD5_DIGEST_LENGTH 16

long wrapfs_encrypt_page_segment(struct page* source_page, struct page* dest_page, char *key, loff_t off_set, loff_t num_of_bytes_to_write );
/*static struct crypto_blkcipher *ceph_crypto_alloc_cipher(void)
 * {
 *     return crypto_alloc_blkcipher("ctr(aes-generic)", 0, 0);
 *     }*/
long  wrapfs_decrypt(struct page *page_data, struct page *decrypted_buf, loff_t page_size, char *key);

int wrapfs_writepage(struct page *page, struct writeback_control *wbc)
{
    int err = -EIO;
    struct inode *inode;
    struct inode *lower_inode;
    struct page *lower_page;
    struct address_space *lower_mapping; /* lower inode mapping */
    gfp_t mask;
    inode = page->mapping->host;
    lower_inode = wrapfs_lower_inode(inode);
    lower_mapping = lower_inode->i_mapping;

    mask = mapping_gfp_mask(lower_mapping) & ~(__GFP_FS);
    lower_page = find_or_create_page(lower_mapping, page->index, mask);
    if (!lower_page) {
	err = 0;
	set_page_dirty(page);
	goto out;
    }

    /* copy page data from our upper page to the lower page */
    copy_highpage(lower_page, page);
    flush_dcache_page(lower_page);
    SetPageUptodate(lower_page);
    set_page_dirty(lower_page);

    if (wbc->for_reclaim) {
	unlock_page(lower_page);
	goto out_release;
    }

    BUG_ON(!lower_mapping->a_ops->writepage);
    wait_on_page_writeback(lower_page); /* prevent multiple writers */
    clear_page_dirty_for_io(lower_page); /* emulate VFS behavior */

    err = lower_mapping->a_ops->writepage(lower_page, wbc);
    printk("IN WRITEPAGE\n");
    if (err < 0)
	goto out_release;

    if (err == AOP_WRITEPAGE_ACTIVATE) {
	err = 0;
	unlock_page(lower_page);
    }

    /* all is well */

    /* lower mtimes have changed: update ours */
    /*wrapfs_copy_attr_times(inode);
     *     fsstack_copy_inode_size(inode,lower_inode);*/
    fsstack_copy_attr_times(inode,lower_inode);

out_release:

    page_cache_release(lower_page);
out:

    unlock_page(page);
    return err;
}

int wrapfs_write_begin(struct file *file, struct address_space *mapping,
	loff_t pos, unsigned len, unsigned flags,
	struct page **pagep, void **fsdata)
{
    printk("\n IN write begin \n");
    struct page *page;
    pgoff_t index;

    index = pos >> PAGE_CACHE_SHIFT;
    page = grab_cache_page_write_begin(mapping, index, flags);
    if (!page)
	return -ENOMEM;

    *pagep = page;
    if (!PageUptodate(page) && (len != PAGE_CACHE_SIZE)) {
	unsigned from = pos & (PAGE_CACHE_SIZE - 1);
	printk("in write_begin,in pageuptodate value of from = %d");

	zero_user_segments(page, 0, from, from + len, PAGE_CACHE_SIZE);
    }
    return 0;
}



int wrapfs_write_end(struct file *file, struct address_space *mapping,
	loff_t pos, unsigned len, unsigned copied,
	struct page *page, void *fsdata)
{
    long err = 0;
    char *buf = NULL;
    long encr_ret = 0; 
    struct file *lower_file;
    mm_segment_t fs_seg;
    loff_t off_set;
    struct page* dest_page=NULL;
    char *key = NULL;
    int num_of_pages, page_index;
    loff_t num_of_bytes_to_write;
    int is_mmap_flag_set;
    int is_key_set, is_append_set = 0;
    struct wrapfs_sb_info *sbi = NULL;


    struct inode *inode = page->mapping->host;
    unsigned from = pos & (PAGE_CACHE_SIZE - 1);
    unsigned to = from + copied;
    loff_t last_pos = 0;

    page_index = (int)page->index; 
    printk ("wrapfs_write_end : page index is %d\n", (int)page->index);

    num_of_pages = (int)(inode->i_size / PAGE_SIZE) ;

    printk ("wrapfs_write_end : number of pages is %d \n", num_of_pages);

    off_set = (((loff_t)(page->index)<< PAGE_CACHE_SHIFT) + 0);
//if not the last page
    if ( page_index < ( num_of_pages))
	num_of_bytes_to_write = PAGE_SIZE;
    else 
	num_of_bytes_to_write = (pos - off_set) + (loff_t)copied ; 


    
    printk("\n wrapfs_write_end: offset1 is %lld \n", off_set);
    printk("value of pos, len and copied is %lld and %u and %u \n", pos, len, copied);
    printk ("wrapfs_write_end : from value is : %u\n",from);
    printk("wrapfs_write_end : to value is %u \n",to); 
//pos is file offset
    //off_set page offset
    last_pos = pos + copied;


    printk("\nNum of bytes to write is %lld \n",num_of_bytes_to_write);
    printk(" value of last_pos is %lld",last_pos);

    /* zero the stale part of the page if we did a short copy */
    if (copied < len) {
	zero_user(page, from + copied, len - copied);
    }

    if (!PageUptodate(page))
	SetPageUptodate(page);
    /*
     *  * No need to use i_size_read() here, the i_size
     *   * cannot change under us because we hold the i_mutex.
     *    */
    printk("\n before updating %lld: \n", inode->i_size);
    if (last_pos > inode->i_size)
	i_size_write(inode, last_pos);

    printk("\n value of isize after updating %lld: \n", inode->i_size); 


    lower_file = wrapfs_lower_file(file);

    if(!lower_file)
    { 
	return -EIO;
    }
  

#ifdef WRAPFS_CRYPTO	
	sbi = (struct wrapfs_sb_info*)(file->f_path.dentry->d_sb->s_fs_info);
    /*is_mmap_flag_set = wrapfs_get_mmap_flag(file->f_dentry->d_sb);
     *  is_key_set = wrapfs_get_aes_key(file->f_dentry->d_sb, NULL);*/

    if(sbi->sb_key != NULL) {
	printk("printing key---> %s",(unsigned char *)sbi->sb_key);

	dest_page = alloc_page(GFP_USER);
	if (dest_page == NULL)
	{
	    printk ("alloc page for dest failed !!\n");
	    goto cleanup;
	} 
	encr_ret = wrapfs_encrypt_page_segment(page,dest_page, sbi->sb_key,off_set, num_of_bytes_to_write );
	printk ("wrapfs_encrypt_page_segment is returning : %ld\n", encr_ret);

    }

#endif

	
	/*if(sbi->sb_key != NULL) 
	buf = kmap(dest_page);
	else
	buf = kmap(page);

*/ 
#ifdef WRAPFS_CRYPTO
		if(sbi->sb_key != NULL)
			buf = kmap(dest_page);
#else if 
	    buf = kmap(page);
#endif
	/*printk("the buf content is %s", buf);*/

    printk("value of offset is %lld", off_set);

    if (((lower_file->f_flags) & O_APPEND) == O_APPEND ) {
	lower_file->f_flags = lower_file->f_flags & ~O_APPEND;
	is_append_set = 1;
    }

    fs_seg = get_fs();
    set_fs(get_ds());
    err = vfs_write(lower_file, buf, num_of_bytes_to_write, &off_set );
    set_fs(fs_seg);
    mark_inode_dirty_sync(inode);

    if (is_append_set == 1) {
	lower_file->f_flags = (lower_file->f_flags & O_APPEND);
	is_append_set = 0;
    }

    printk("wrapfs_write_end : vfs write returned %ld \n ",err );

cleanup : 
    if(!buf)
    { 
#ifdef WRAPFS_CRYPTO
		if(sbi->sb_key != NULL)
			kunmap(dest_page);
#else if 
	    kunmap(page);
#endif
    }


    set_page_dirty(page);
    unlock_page(page);
    page_cache_release(page);


    return copied;
}





int wrapfs_readpage(struct file *file, struct page *page)
{
    printk("IN READPAGE\n");
    int err,err1;
    struct file *lower_file;
    struct inode *inode;
    mm_segment_t old_fs;
    char *page_data = NULL;
    mode_t orig_mode;
    /*#ifdef WRAPFS_CRYPTO*/
    struct wrapfs_sb_info *sbi = NULL;
    
    struct page * decrypt_page = NULL;
    char *decrypted_buf = NULL;

    /*#endif*/
    lower_file = wrapfs_lower_file(file);
    /* FIXME: is this assertion right here? */
    BUG_ON(lower_file == NULL);
    inode = file->f_path.dentry->d_inode;
    page_data = (char *) kmap(page);
    /*:wq
      Use vfs_read because some lower file systems don't have a
     readpage method, and some file systems (esp. distributed ones)
      don't like their pages to be accessed directly. Using vfs_read
     may be a little slower, but a lot safer, as the VFS does a lot of
      the necessary magic for us.
     */
    lower_file->f_pos = page_offset(page);
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    /*
     generic_file_splice_write may call us on a file not opened for
     reading, so temporarily allow reading.
     */
    orig_mode = lower_file->f_mode;
    lower_file->f_mode |= FMODE_READ;
    err = vfs_read(lower_file, page_data, PAGE_CACHE_SIZE,
	    &lower_file->f_pos);
    lower_file->f_mode = orig_mode;
    set_fs(old_fs);
    /*#ifdef WRAPFS_CRYPTO*/
    printk("wrapfs_crypto is defined");
    /* At this point, we have the entire page from lower file system in
     page_data. If WRAPFS_CRYPTO is set, we need to decrypt page_data
     and store it back in page_data.
     */

	#ifdef WRAPFS_CRYPTO

    sbi = (struct wrapfs_sb_info*)file->f_path.dentry->d_sb->s_fs_info;
    decrypt_page = alloc_page(GFP_USER);
    
    if (sbi->sb_key!=NULL) {
      printk("\n decryption starting");

      err1 = wrapfs_decrypt(page, decrypt_page,PAGE_CACHE_SIZE,sbi->sb_key);
    
      if(err1 < 0) {
      printk("\n wrapfs_decrypt failed!!");
      kunmap(page);
    //  kfree(decrypted_buf);
      err = -EINVAL;
      goto out;
     }
     decrypted_buf = (char *)kmap(decrypt_page); 
     printk("\n decryption successful. decrypted data %s",decrypted_buf);
     memcpy(page_data, decrypted_buf, PAGE_CACHE_SIZE);
     printk("\n data after memcopying in page_data %s", page_data);
     // kfree(decrypted_buf);
     kunmap(decrypt_page);
    // kfree(decrypted_buf);
    }
    //lower_file->f_mode = orig_mode;
    //set_fs(old_fs);
#endif
    if (err >= 0 && err < PAGE_CACHE_SIZE)
	memset(page_data + err, 0, PAGE_CACHE_SIZE - err);
    kunmap(page);
	
    if (err < 0)
	goto out;
    err = 0;
    /* if vfs_read succeeded above, sync up our times 
     * fsstack_copy_inode_size(inode,lower_inode);*/
    fsstack_copy_attr_times(inode,lower_file->f_path.dentry->d_inode);
    flush_dcache_page(page);
    /*
     we have to unlock our page, b/c we _might_ have gotten a locked
     page. but we no longer have to wakeup on our page here, b/c
     UnlockPage does it
     */
out:
    if (err == 0)
	SetPageUptodate(page);
    else
	ClearPageUptodate(page);
    unlock_page(page);
    /*wrapfs_check_file(file);
     * wrapfs_read_unlock(file->f_path.dentry->d_sb);*/
    return err;
}



/*int wrapfs_decrypt(char *input, int inputlen, char *output, int outputlen,
	char *key, int keylen)
{
    printk("am in decrypt");
    struct crypto_blkcipher *tfm = NULL;
    struct blkcipher_desc desc;
    struct scatterlist src[1], dst[1];
    unsigned int retval = 0;

    tfm = crypto_alloc_blkcipher("ctr(aes)", 0, 0);
    if (IS_ERR(tfm)) {
	printk(KERN_INFO "crypto_alloc_blkcipher failed\n");
	return -EINVAL;
    }

    desc.tfm = tfm;
    desc.flags = 0;

    retval = crypto_blkcipher_setkey(tfm, key, keylen);
    if (retval) {
	printk(KERN_INFO "crypto_blkcipher_setkey failed\n");
	crypto_free_blkcipher(tfm);
	return -EINVAL;
    }

    sg_init_table(src, 1);
    sg_set_buf(&src[0], input, inputlen);
    sg_init_table(dst, 1);
    sg_set_buf(dst, output, outputlen);

    retval = crypto_blkcipher_decrypt(&desc, dst, src, inputlen);
    crypto_free_blkcipher(tfm);
    printk("\n decrypted");
    return retval;
}
*/

#ifdef WRAPFS_CRYPTO
long wrapfs_decrypt(struct page  *source_page, struct page *dest_page, loff_t page_size, char *key)

{
    struct crypto_blkcipher *tfm = NULL;
    struct blkcipher_desc desc;
    
    struct scatterlist src, dst;
    
    unsigned int ret = 0;
    /*
    printk ("num of bytes : %lld\n", num_of_bytes_to_write);
    printk ("offset is : %lld\n", off_set);
    */
    tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
    
    if (IS_ERR(tfm)) {
        printk("failed to load transform Err123445 !!\n");
        ret = -EINVAL;
        goto out;
    }
    desc.tfm = tfm;
    desc.flags = 0;
    
    
    //printk("\n key lengthi nside encryption function is %d\n", lengthi);
    printk("\n Key value inside encr is : |%s| \n", key);
    ret = crypto_blkcipher_setkey(tfm, key,strlen(key));
    if (ret) {
        printk("setkey() failed flags !!\n");
        ret = -EINVAL;
        goto out;
    }


    sg_init_table(&src, 1);
    sg_set_page(&src, source_page, page_size,0);
    sg_init_table(&dst, 1);
    sg_set_page(&dst, dest_page, page_size,0);

    ret = crypto_blkcipher_decrypt(&desc, &dst, &src, page_size);
    printk ("Ret returned by crypto_blkcipher_encrypt is : %ld\n", ret);
    
    if (ret >= 0)
        ret = 0;
    
out:
    if (desc.tfm)
    {
        crypto_free_blkcipher(tfm);
        tfm = NULL;
    }
    
    return ret;
    
}


long wrapfs_encrypt_page_segment(struct page* source_page, struct page* dest_page, char *key, loff_t off_set, loff_t num_of_bytes_to_write )

{
    struct crypto_blkcipher *tfm ;
    struct blkcipher_desc desc;

    struct scatterlist src, dst;

    unsigned int ret = 0;

    printk ("num of bytes : %lld\n", num_of_bytes_to_write);
    printk ("offset is : %lld\n", off_set);

    tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);

    if (IS_ERR(tfm)) {
	printk("failed to load transform Err123445 !!\n");
	ret = -EINVAL;
	goto out;
    }
    desc.tfm = tfm;
    desc.flags = 0;


    printk("\n key lengthi nside encryption function is %d\n", strlen(key));
    printk("\n Key value inside encr is : |%s| \n", key);
    ret = crypto_blkcipher_setkey(desc.tfm, key,strlen(key));
    if (ret) {
	printk("setkey() failed flags !!\n");
	ret = -EINVAL; 
	goto out;
    }

    sg_init_table(&src, 1);
    sg_set_page(&src, source_page, num_of_bytes_to_write,0);
    sg_init_table(&dst, 1);
    sg_set_page(&dst, dest_page, num_of_bytes_to_write,0);

    ret = crypto_blkcipher_encrypt(&desc, &dst, &src, num_of_bytes_to_write);
    printk ("Ret returned by crypto_blkcipher_encrypt is : %ld\n", ret);

    if (ret >= 0)
	ret = 0;

out:
    if (desc.tfm)
    {
	crypto_free_blkcipher(tfm);
 	tfm = NULL;
    }

    return ret;

}

#endif

static int wrapfs_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    int err;
    struct file *file, *lower_file;
    const struct vm_operations_struct *lower_vm_ops;
    struct vm_area_struct lower_vma;

    memcpy(&lower_vma, vma, sizeof(struct vm_area_struct));
    file = lower_vma.vm_file;
    lower_vm_ops = WRAPFS_F(file)->lower_vm_ops;
    BUG_ON(!lower_vm_ops);

    lower_file = wrapfs_lower_file(file);
    /*
     *      * 	 * XXX: vm_ops->fault may be called in parallel.  Because we have to
     *           * 	 	 * resort to temporarily changing the vma->vm_file to point to the
     *                * 	 	 	 * lower file, a concurrent invocation of wrapfs_fault could see a
     *                     * 	 	 	 	 * different value.  In this workaround, we keep a different copy of
     *                          * 	 	 	 	 	 * the vma structure in our stack, so we never expose a different
     *                               * 	 	 	 	 	 	 * value of the vma->vm_file called to us, even temporarily.  A
     *                                    * 	 	 	 	 	 	 	 * better fix would be to change the calling semantics of ->fault to
     *                                         * 	 	 	 	 	 	 	 	 * take an explicit file pointer.
     *                                              * 	 	 	 	 	 	 	 	 	 */
    lower_vma.vm_file = lower_file;
    err = lower_vm_ops->fault(&lower_vma, vmf);
    return err;
}

/*
 *  *  * XXX: the default address_space_ops for wrapfs is empty.  We cannot set
 *   *   * our inode->i_mapping->a_ops to NULL because too many code paths expect
 *    *    * the a_ops vector to be non-NULL.
 *     *     */
const struct address_space_operations wrapfs_aops = {
    /* empty on purpose */
};

const struct address_space_operations wrapfs_mmap_aops = {
    .writepage      = wrapfs_writepage,
    .write_end	= wrapfs_write_end,
    .write_begin	= wrapfs_write_begin,
    .readpage	= wrapfs_readpage,
};

const struct vm_operations_struct wrapfs_vm_ops = {
    .fault		= wrapfs_fault,
};


