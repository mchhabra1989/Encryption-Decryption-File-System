/* 					README
 * CSE-506 Operating System (Spring 2013) Homework Assignment #3
 * ADDRESS SPACE OPERATIONS AND ENCRYPTION/DECRYPTION FILE IN WRAPFS
 * GROUP-NO - hw3-cse506g07	
 * Rohan Mehta -108648007
 * Anchal Agarwal- 108997912
 * Manish Chhabra -109136341
*/

We have succesfully implemented Address space operation and encryption and decryption
of file data/pages in wrapfs. We have also implemented Extra credits for Debug operations 
and filename encryption.Decryption works fine with the function but we were not able to 
integrate with the function of wrapfs due to lack of time and resource, but it does encrypt
and decrypt filename.Encryption of filename is done for lookup and symlink.

NEW FILES added in the system.

1) fs/wrapfs/computeKey.c  

This files generate the md5 value for the key which we generate for file page 
encryption and decryption. We are passing the string type password in our user
IOCTL program which passes that string in wrapfs_unlocked_ioctl function in file.c.
there this function for computing md5 is called amnd the key for encrypt/decrpyt 
is generated. We have made use of md5 functions used in HW1/HW2.
				  
2) /usr/src/hw3-cse506g07/ioctl.c

This file is a user ioctl program which is used for setting the key. we send a user
password in that file as a string in the ioctl, which when recieved in wrapfs_unlocked_ioctl 
fucntion calculates the key for encryption and decryption. The length of the character 
needs to be passed should be of 10 CHARACTERS only. This is of constant length which we
are considering. 


3) /usr/src/hw3-cse506g07/user_lseek_test.c

This is a user program for testing the lseek operation on writing and reading data from the
pages of the file. we have used this program to fill in the zeros while encrypting the pages.

4) fs/wrapfs/filename_encrypt.c

This file contains the function used for filename encryption and decryption.
These function are implemented and taken from Fistgen source code available
to us.wrapfs_encode_filename and wrapfs_decode_filename encodes and decodes 
the filenames respectively. They make use of fucntions which are defined in 
file or the header file wrapfs.h like BF_cfb64_encrypt function which is 
in this file. It is the EXTRA_CREDIT_2.

5) /usr/src/hw3-cse506g07/testing.sh

To increase efficiency,we decided to make a script file which is as follows.

umount /tmp
cd /
rmmod wrapfs
cd /usr/src/hw3-cse506g07
make
make modules
make modules_install install
mount -t wrapfs /n/scratch/ /tmp -o mmap

To mount with debug option enabled we just need to change 

mount -t wrapfs /n/scratch/ /tmp -o mmap,debug=X , where X is the number
for which we need to enable the debug option as stated in hw3 writeup.

FILES MODIFIED :-

 fs/wrapfs/wrapfs.h
 fs/wrapfs/main.c
 fs/wrapfs/mmap.c
 fs/wrapfs/dentry.c
 fs/wrapfs/file.c
 fs/wrapfs/inode.c
 fs/wrapfs/lookup.c
 fs/wrapfs/super.c
 .config file used same as of HW2

IMPLEMENTATION :---

TASK2:- ADDRESS SPACE OPERATIONS

For the operation to work we have modified the file mmap.c and have added necessary 
address_space operations such that individual data pages at the upper layer could 
have different data from those at the lower layer. So, we have implemented these 
operations by referencing to the code for ECRYPTFS. We have taken functions and modified 
according to the requirement of our project.

for address space operations to get enable, we mount the wrapfs with mmap option enabled

mount -t wrapfs /n/scratch/ /tmp -o mmap

This enables operation. if there is no mmap option availanle, it mounts wrapfs with the 
normal vm_ops operations. To enable and disable we are making use of int variable
mmap_option_set. this flag variable is declared in the superblock structure in wrapfs.h
and used in main. c to enable and disable the mmap option.

wrapfs_parse_options function is created in main.c which parses the options we recieve in runtime.
So, when we recieve mmap, it enables the flag and set it to 1, otherwise it is set to 0 and normal
operations are executed.

When mmap_option_set is set to 1 , then we check in lookup.c struct inode *wrapfs_iget function 
to enable the mmap functions.otherwise, normal fops are run.

in mmap.c a structure is created to register mmap operations

const struct address_space_operations wrapfs_mmap_aops = {
    .writepage      = wrapfs_writepage,
    .write_end		= wrapfs_write_end,
    .write_begin	= wrapfs_write_begin,
    .readpage		= wrapfs_readpage,
	.bmap			= wrapfs_bmap,	
};

also, in file.c we have created another structure to support mmap operations.

const struct file_operations wrapfs_main_mmap_fops = { 
    .llseek         = generic_file_llseek,
    .read           = do_sync_read,
    .write          = do_sync_write,
    .aio_read  		= generic_file_aio_read,
    .aio_write 		= generic_file_aio_write,
    .unlocked_ioctl = wrapfs_unlocked_ioctl,
	.mmap			= generic_file_mmap,
#ifdef CONFIG_COMPAT
    .compat_ioctl   = wrapfs_compat_ioctl,
#endif
    .open           = wrapfs_open,
    .flush          = wrapfs_flush,
    .release        = wrapfs_file_release,
    .fsync          = wrapfs_fsync,
    .fasync         = wrapfs_fasync,
};

Now, once they are enabled, it runs the function defined in mmap.c

1) wrapfs_writepage -
The code for writepage is taken from ecryptfs and implemented for part 1 of address space
operations. significant changes are done for part 2 of data encryption and ecryption.

2)wrapfs_readpage -
The code for writepage is taken from ecryptfs and implemented for part 1 of address space
operations. significant changes are done for part 2 of data encryption and ecryption.

3)wrapfs_read_lower_page_segment-

This function is also taken from ecryptfs and called inside the write begin function to 
read the lower page data.

4)wrapfs_write_begin

5)wrapfs_write_end


These are the functions implemented and taken from ecryptfs. this function contains code
for encrypting and decrypting file pages. it is explained in next section.


TASK 3: DATA PAGE ENCRYPTION

To encrypt and decrypt we have made use of the function wrapfs_encrypt and wrapfs_decrypt in the mmap.c
To make this working we had to enable the AES and CTR cipher for encryption in the kernel config.
We have created a user ioctl program that generates the key for encrypting and decrypting data pages,
Key is being stored in the structure of superblock wrapfs_struct_info and used with the superblock object
wherever required. 






EXTRA CREDITS:-

1)	debugging/tracing support

We have implemneted the debugging support for the different blocks as mentioned in the writeup.
To enable this debug extra credit,Enable the #define EXTRA_CREDIT_1 in the wrapfs.h .

For this, we have mnade changes in main.c .firstly, flags for all six debug operations are defined
in the super block struct info in wrapfs.h and also in the main .c locally.

#ifdef EXTRA_CREDIT_1
	int debug_super_block_ops;
	int debug_inode_ops;
	int debug_dentry_ops;
	int debug_file_ops;
	int debug_address_space_ops;
	int debug_all_other_ops;
#endif

set_enable_debug function is made in main.c which enables the debug for the 
respective blocks. it sets the value of the flag for the respective operation 
to 1, and then based on this vlaue of flag, our custom printk statements gets 
printed during Debug operation. eg : if we pass 3 as a decimal value for opt, 
3 in decimal is 0x01 + 0x02, so this'll enable debugging for superblock and inode
ops. So, loop condition is made like that.	

0x01: enable debugging for superblock ops
0x02: enable debugging for inode ops
0x04: enable debugging for dentry ops
0x10: enable debugging for file ops
0x20: enable debugging for address_space ops
0x40: enable debugging for all other ops

for eg: mount -t wrapfs \n\scratch \tmp -0 mmap,debug=32

it enables debug for address space operations as 32 in decimal is 20 in hex decimal.
So, it enables debug suppport for address space.

	mount -t wrapfs \n\scratch \tmp -0 mmap,debug=3	
so this'll enable debugging for superblock and inode ops

Also,
	mount -t wrapfs \n\scratch \tmp -0 mmap,debug=0
if we mount it with debug=0 , then the debug is disbaled and we do not get any printks.

As far as remount condiion goes, it does remount with the option 0, but debug options are not
disbaled in that case, we havmnt taken care of that.

Our debug operation works for the specific values and the combination of that as mentioned 
in the writeup, but no check is made for arbitary values. So, it only runs valid in the
case of mentioning right values in it.Passing arbitary values may enable other debug operations
which we havent handle. but normal debug works.

We have looked into ecryptfs custom printk statement making use of UDBG printk to define our own
as stated in writeup for assignment.

eg: #define debug_super_block_ops(flag, fmt, arg...) \ 
	flag ? printk(KERN_DEFAULT "DBG:%s:%s:%d: " fmt "\n", \
		__FILE__, __func__, __LINE__, ## arg) : 1;
		
this statement define custom pritnk function named  debug_super_block_ops, which enables this printk k
depending upon the flag value which is for example is WRAPFS_SB(sb)->debug_super_block_ops =debug_super_block_ops;
used for super block as defined when super block object is made in  wrapfs_super function in main.c

if the value for this flag is 1, then it is enable and printk are printed. if it is 0, then it does not.

There are two printk statements enabled in each function. One at the start of it displaying the function name
it is in, and one at the end of it displaying the err number returned by the function.

Necessary printk are then added in the files for specific type like inode.c for inode operations,file.c for file 
operations and similarly for  dentry.c, super.c, mmap.c for address space operation and for all other operations
the printks are define in wrapfs_fault function in mmap.c

It is also implemented in lookup.c depending upon the operations defined inside the functions. so, we make use of
inode operaion, dentry operation as specified there.

2) FILENAME ENCRYPTION AND DECRYPTION
  
 To enable this extra credit , we need to enable #define EXTRA_CREDIT_2 in the wrapfs.h. We have implemented this
extra credit partially, we are able to encrypt the filenames successfully in the lookup.c file in the lookup and 
symlink functions. but decryption we are unabel to deployed to the functions defined in wrapfs. But, defualt
decrypt function works fine and decrypt the filenames when we print them inside the function.

due to lack of time , we were not able to implement inside the wrapfs_function. but encryption is deployed and 
working fine.

We have made use of the encryption and decryption code from FISTGEN which make use of blowfish algorithm to encrypt
and decrypt filename. neccesaary functions for encrypt and decrypt filename are declared in the filename_encrypt.c
file. and necessary inclusions of headers and function are defined in wrapfs.h are defined under EXTRA_CREDIT_2.

To make it run, we generate the key from our user program ioctl.c by ./a.out /tmp/filename.c and then this key
is passed inside the funtion of encode and decode and then we open a new file by vim /tmp/filename.c, it gets encrypted
and when we ls to view the files inside the directory it shows the encrypted name.

wrapfs_encode_filename is used to encode the filename inside the filename_encrypt.c. it is called in lookup and symlink 
function in lookup.c and necessary checks have been made. if this extra credit is enabled it saves the encoded name other 
wise it stores the  normal name.

Decoding of filenames have been done partially, that is we have implemented the function for it in filename_encrypt.c ,
wrapfs_decode_filename which decodes the filename . but we havent implemented it inside any function like readdir, filldir 
etc.
If we printk the decoded name inside the function then it prints the decrypted name. Thats why it is partial implementation.
But both encode and decode functions runs ok and prooduce results.

To enable the decode printk to see if the function is working fine we have commented properly how to do it in the file
filename_encrypt.c file. So, to see decode functionality, you can enable the printk in that function.

EXTRA IMPLEMENTATIONS:-

1) We have also made use of shrink_dcache_sb FUNCTION to free the existing pages in the cache.this is done in wrapfs_unlocked_ioctl 
before setting the key this was discussed in the office hours with professor, so we implememnted.
This is an extra thing implemented as it might happen that we read some pages from chache which are not the desired pages we want, that
is they might be stale, so reading a stale page is a loophole. hence we implemented that.

2) To generate the key we have made us of md5 function which is defined in computeKey.c . We can pass a password type
 string to this md5 throiugh our ioctl program and it generates 32 byte key.

3) both the extra credits are implemented. one is done partially as mentioned above. 


RESOURCES and CITATIONS:
1) ECRYPTFS CODE and UNIONFS Code
2) FISTGEN Encrypting and decrypting filenames
3) http://www.makelinux.net/ldd3/chp-4-sect-2 for referencing custom printk statements
4) http://lxr.linux.no/linux+v3.2/fs/ecryptfs/ecryptfs_kernel.h#L515 for referencing curom printk in ecryptfs
5) Linux LXR for code and understanding some syntax.
			  