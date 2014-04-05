#include <err.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define WRAPFS_MAGIC 's'
#define WRAPFS_IOCSETD  _IOW(WRAPFS_MAGIC, 2 , char *)

int main(int argc, char*argv[])
{
    printf("am n user prog \n");
    int fd; 
    int ret = 0;
    char *val;
    val = "manish";
    char *filename = argv[1];
    fd = open(argv[1], O_RDONLY);
   // fd=fopen(filename,"r");
    printf("in user, file descriptor is %d \n", fd);
   // if(fd)
    //  err(1,"open");
	//printf("Value: %s \n",(char *)val);
    ret = ioctl(fd,WRAPFS_IOCSETD,(char *)val);
    printf("return value from ioctl-- > %d \n",ret);
    if(ret == -1) 
        err(1,"CRYPTFILE! \n");
    close(fd);
    return (0);
}


