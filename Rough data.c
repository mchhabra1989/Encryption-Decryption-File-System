insmod /usr/src/hw3-cse506g07/fs/wrapfs/wrapfs.ko

int wrapfs_commit_write(struct file *file, struct page *page,
                                  unsigned from, unsigned to)
  {
          int err = -ENOMEM;
          struct inode *inode, *lower_inode;
          struct file *lower_file = NULL;
          unsigned bytes = to - from;
          char *page_data = NULL;
          mm_segment_t old_fs;
  
          BUG_ON(file == NULL);
 
          //unionfs_read_lock(file->f_path.dentry->d_sb, UNIONFS_SMUTEX_PARENT);
          //err = unionfs_file_revalidate(file, true);
          //if (unlikely(err))
            //      goto out;
          //unionfs_check_file(file);
  
          inode = page->mapping->host;
  
          if (WRAPFS_F(file) != NULL)
                  lower_file = wrapfs_lower_file(file);
  
          /* FIXME: is this assertion right here? */
          BUG_ON(lower_file == NULL);
  
          page_data = (char *)kmap(page);
          lower_file->f_pos = page_offset(page) + from;
  
          /*
           * We use vfs_write instead of copying page data and the
           * prepare_write/commit_write combo because file system's like
           * GFS/OCFS2 don't like things touching those directly,
           * calling the underlying write op, while a little bit slower, will
           * call all the FS specific code as well
           */
          old_fs = get_fs();
          set_fs(KERNEL_DS);
          err = vfs_write(lower_file, page_data + from, bytes,
                          &lower_file->f_pos);
          set_fs(old_fs);
  
          kunmap(page);
  
          if (err < 0)
                  goto out;
  
          /* if vfs_write succeeded above, sync up our times/sizes */
          lower_inode = lower_file->f_path.dentry->d_inode;
          if (!lower_inode)
                  lower_inode = wrapfs_lower_inode(inode);
          BUG_ON(!lower_inode);
          fsstack_copy_inode_size(inode, lower_inode);
          //unionfs_copy_attr_times(inode);
          mark_inode_dirty_sync(inode);
  
  out:
          if (err < 0)
                  ClearPageUptodate(page);
  
          //unionfs_check_file(file);
          //unionfs_read_unlock(file->f_path.dentry->d_sb);
          return err;             /* assume all is ok */
  }
  
  
  int wrapfs_write_lower(struct inode *wrapfs_inode, char *data,
                           loff_t offset, size_t size,struct file *file)
 {
          struct file *lower_file;
          mm_segment_t fs_save;
          ssize_t rc;
  
          lower_file = wrapfs_lower_file(file);
          if (!lower_file)
                  return -EIO;
          fs_save = get_fs();
          set_fs(get_ds());
          rc = vfs_write(lower_file, data, size, &offset);
          set_fs(fs_save);
          mark_inode_dirty_sync(wrapfs_inode);
          return rc;
  }
  
  int wrapfs_write_begin(struct file *file, struct address_space *mapping,
                          loff_t pos, unsigned len, unsigned flags,
                          struct page **pagep, void **fsdata)
  {
          struct page *page;
          pgoff_t index;
  
          index = pos >> PAGE_CACHE_SHIFT;
  
          page = grab_cache_page_write_begin(mapping, index, flags);
          if (!page)
                  return -ENOMEM;
		   //printk("IN write begin");
          *pagep = page;
          if (!PageUptodate(page) && (len != PAGE_CACHE_SIZE)) {
                  unsigned from = pos & (PAGE_CACHE_SIZE - 1);
  
                  zero_user_segments(page, 0, from, from + len, PAGE_CACHE_SIZE);
          }
          return 0;
  }

int wrapfs_write_end(struct file *file, struct address_space *mapping,
                          loff_t pos, unsigned len, unsigned copied,
                          struct page *page, void *fsdata)
  {
  	
          struct inode *inode = page->mapping->host;
          loff_t last_pos = pos + copied;
  
          /* zero the stale part of the page if we did a short copy */
          if (copied < len) {
                  unsigned from = pos & (PAGE_CACHE_SIZE - 1);
  
                  zero_user(page, from + copied, len - copied);
          }
          if (!PageUptodate(page))
                  SetPageUptodate(page);
          /*
           * No need to use i_size_read() here, the i_size
           * cannot change under us because we hold the i_mutex.
           */
          if (last_pos > inode->i_size)
                  i_size_write(inode, last_pos);
		  //printk("In write end");
          set_page_dirty(page);
          unlock_page(page);
          page_cache_release(page);
  
          return copied;
  }
  
  int wrapfs_read_lower_page_segment(struct page *page_for_wrapfs,
                                      pgoff_t page_index,
                                      size_t offset_in_page, size_t size,
                                      struct inode *wrapfs_inode,struct file *file)
 {
         char *virt;
         loff_t offset;
         int rc;
 
         offset = ((((loff_t)page_index) << PAGE_CACHE_SHIFT) + offset_in_page);
         virt = kmap(page_for_wrapfs);
         rc = wrapfs_read_lower(virt, offset, size, wrapfs_inode,file);
         if (rc > 0)
                 rc = 0;
         kunmap(page_for_wrapfs);
         flush_dcache_page(page_for_wrapfs);
         return rc;
 }
 
 int wrapfs_read_lower(char *data, loff_t offset, size_t size,
                         struct inode *wrapfs_inode,struct file *file)
 {
         struct file *lower_file;
         mm_segment_t fs_save;
         ssize_t rc;
 
         lower_file = wrapfs_lower_file(file);
         if (!lower_file)
                 return -EIO;
         fs_save = get_fs();
         set_fs(get_ds());
         rc = vfs_read(lower_file, data, size, &offset);
         set_fs(fs_save);
         return rc;
 }
 
 extern int wrapfs_writepage(struct page *page, struct writeback_control *wbc);
extern int wrapfs_write_begin(struct file *file, struct address_space *mapping,
                          loff_t pos, unsigned len, unsigned flags,
                          struct page **pagep, void **fsdata);

extern int wrapfs_write_end(struct file *file, struct address_space *mapping,
                          loff_t pos, unsigned len, unsigned copied,
                          struct page *page, void *fsdata);
extern int wrapfs_write_lower_page_segment(struct inode *wrapfs_inode,
                                        struct page *page_for_lower,
                                        size_t offset_in_page, size_t size,struct file *file);
extern  int wrapfs_write_lower(struct inode *wrapfs_inode, char *data,
                           loff_t offset, size_t size, struct file *file);	
extern int wrapfs_readpage(struct file *file, struct page *page);	

 pgoff_t index = pos >> PAGE_CACHE_SHIFT;
         unsigned from = pos & (PAGE_CACHE_SIZE - 1);
         unsigned to = from + copied;
         struct file *lower_file;
         struct inode *wrapfs_inode = mapping->host;
		 mm_segment_t fs_save;
		 char *virt;
		 loff_t offset;
		 int rc;
         /*struct ecryptfs_crypt_stat *crypt_stat =
                 &ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat;*/
         
		 lower_file = wrapfs_lower_file(file);
         /*ecryptfs_printk(KERN_DEBUG, "Calling fill_zeros_to_end_of_page"
                         "(page w/ index = [0x%.16lx], to = [%d])\n", index, to);*/
         //if (!(crypt_stat->flags & ECRYPTFS_ENCRYPTED)) {
		 rc = wrapfs_write_lower_page_segment(file,wrapfs_inode, page, 0,
												to);
		 if (!rc) {
				 rc = copied;
				 fsstack_copy_inode_size(wrapfs_inode,
						 wrapfs_lower_inode(wrapfs_inode));
		 }
		 goto out;
         //}
         /*if (!PageUptodate(page)) {
                 if (copied < PAGE_CACHE_SIZE) {
                         rc = 0;
                         goto out;
                 }*/
                 //SetPageUptodate(page);
         //}
         /* Fills in zeros if 'to' goes beyond inode size */
         //rc = fill_zeros_to_end_of_page(page, to);
         /*if (rc) {
                 ecryptfs_printk(KERN_WARNING, "Error attempting to fill "
                         "zeros in page with index = [0x%.16lx]\n", index);
                 goto out;
         }*/
         /*rc = ecryptfs_encrypt_page(page);
         if (rc) {
                 ecryptfs_printk(KERN_WARNING, "Error encrypting page (upper "
                                 "index [0x%.16lx])\n", index);
                 goto out;
         }*/
         if (pos + copied > i_size_read(wrapfs_inode)) {
                 i_size_write(wrapfs_inode, pos + copied);
                 /*printk(KERN_DEBUG, "Expanded file size to "
                         "[0x%.16llx]\n",
                         (unsigned long long)i_size_read(wrapfs_inode));*/
         }
         /*rc = ecryptfs_write_inode_size_to_metadata(ecryptfs_inode);
         if (rc)
                 printk(KERN_ERR "Error writing inode size to metadata; "
                        "rc = [%d]\n", rc);
         else*/
                 //rc = copied;
 out:
         unlock_page(page);
         page_cache_release(page);
         return rc;