/*
 * Written by Thierry Vignaud,
 * heavilly modified for msec purpose by Vandoorselaere Yoann.
 *
 * This code is copyrighted by Mandrakesoft [(c) 2000] and is released under
 *  the GPL licence
 */


/*
 * TODO
 * +++	hash tables or btree to stock already searched uid/gid for speed
 *		Pb: since linux-2.3.4x, uid & gid are 32 bits wide ... => BTREE?
 *		static char **uid_hash, **gid_hash;
 *
 * +++	check for open & I/O error on log files ...
 * +++	Yoann scripts should avoid /dev if devfs is mounted (either by testing
 *		if /dev is mounted by devfs or if [ -f /dev/.devfsd ] => see with
 *		Yoann
 * ---	disable 'cannot stat ...' warning (???) => better log them SECURITY_LOG
 * ---	disable write test on links => OK
 */

/*
 * (Vandoorselaere Yoann)
 * Done : 
 * - Don't handle FTW_DNR case, since it will print warning for /proc file.
 * - Don't walk trought /dev & /proc.
 * - We don't need to handle all of the ftw flag, just the FTW_F & FTW_D one :)
 * - Use FTW_PHYS to not follow symbolic link.
 * - Do not use getenv to get the root directory.
 * - Use argv instead of a DIR variable to get directory to scan.
 * - Free directory after use when allocated for appending a '/'.
 * - We do not need __USE_XOPEN_EXTENDED definition.
 */

#include <stdlib.h>
#include <stdio.h>

#define __USE_XOPEN_EXTENDED
#include <ftw.h>

#include <sys/stat.h>

/* For NSS managment */
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>

#include <string.h>


#ifdef __GNUC__
#define inline
#else
#warning upgrade your so-called system to a real OS such as GNU/Linux
#endif

/*
 * Log files
 */
static FILE *suid_fd;
static FILE *sgid_fd;
static FILE *unowned_user_fd;
static FILE *unowned_group_fd;
static FILE *writeable_fd;

static int traverse(const char *file, const struct stat *sb, int flag, struct FTW *s)
{
	struct passwd *u_nss_data;
	struct group *g_nss_data;
        
	if (strncmp(file, "//", 2) == 0 )
                /*
                 * handle bogus glibc ftw
                 * else we won't print only one '/' in front of file names
                 */
                file++;

        if (strncmp("/proc", file, 5) == 0)
                return 0;
        if (strncmp("/dev", file, 4) == 0)
                return 0;
        
	switch (flag) {
		/*
                 * Here is a difference with security-check.sh:
		 * we don't check for regular files only for Set-UID et Set-GID but
		 * to directories too. Idem for world writable directories ...
		 */

        case FTW_F:
                /*
                 * Regular file
                 *
                 * printf("%s\n", file);
                 */
            
                /*
                 * Is writeable check.
                 */
		if (sb->st_mode & 0002)
			fprintf(writeable_fd, "%s\n", file);

                /*
                 * Is suid root check.
                 */
                if ((sb->st_mode & S_ISUID) && (sb->st_uid == 0))
			fprintf(suid_fd, "%s\n", file);

                /*
                 * Is suid group check.
                 */
                if (sb->st_mode & S_ISGID)
			fprintf(sgid_fd, "%s\n", file);

        case FTW_D:
                /*
                 * Unowned user check.
                 */
		u_nss_data = getpwuid(sb->st_uid);
		if (u_nss_data == NULL)
			fprintf(unowned_user_fd, "%s\n", file);

                /*
                 * Unowned group check.
                 */
                g_nss_data = getgrgid(sb->st_uid);
		if (g_nss_data == NULL)
			fprintf(unowned_group_fd, "%s\n", file);
		break;
	}
	return 0;
}

/* This function opens all log files */
__inline__ static void init()
{
	static const char *mode = "w+";

        suid_fd = fopen(getenv("SUID_ROOT_TODAY"), mode);
        if ( ! suid_fd ) {
                perror("fopen (suid_root_today)");
                exit(1);
        }
        
        sgid_fd = fopen(getenv("SUID_GROUP_TODAY"), mode);
        if ( ! sgid_fd ) {
                perror("fopen (suid_group_today)");
                exit(1);
        }

        writeable_fd = fopen(getenv("WRITEABLE_TODAY"), mode);
        if ( ! writeable_fd ) {
                perror("fopen (writeable_today)");
                exit(1);
        }
        
	unowned_user_fd = fopen(getenv("UNOWNED_USER_TODAY"), mode);
        if ( ! unowned_user_fd ) {
                perror("fopen (unowned_user_today)");
                exit(1);
        }
        
        unowned_group_fd = fopen(getenv("UNOWNED_GROUP_TODAY"), mode);
        if ( ! unowned_group_fd ) {
                perror("fopen (unowned_group_today)");
                exit(1);
        }
}

int main(int argc, char **argv)
{
	char *directory;
	int res = 0, i;
        int ctrl = 0;

        if ( argc < 2 ) {
                fprintf(stderr, "Please give directory as argument.\n");
                fprintf(stderr, "%s /usr/sbin /sbin\n\n", argv[0]);
                exit(1);
        }
        
        /* open all log files */
	init();

        for ( i = 0; i < argc; i++ ) {

                if (strcmp(argv[0], "/") != 0) {
                        /*
                         * We need to add a final '/' to the base directory name else the
                         * FTW_MOUNT option of nftw won't work. i.e. : /mnt/cdrom is on the /
                         * fs (it is the directory on which a CD is mounted) whereas
                         * /mnt/cdrom/ is the mounted directory.
                         * Hopefully, find has the same "bug"
                         */
                    
                        ctrl = 1;
                        directory = ( char * ) malloc((strlen(argv[i]) + 1));
                        if ( ! directory ) {
                                perror("malloc");
                                exit(1);
                        }
                        
                        strcpy(directory, argv[i]);
                        strcat(directory, "/");
                } else directory = argv[i];
                
                res = nftw(directory, traverse, (int) 500, FTW_PHYS | FTW_MOUNT | FTW_CHDIR);
                if ( ctrl ) {
                        free(directory);
                        ctrl = 0;
                }
        }
        
	/*
         * close all log files
         */
        
	fclose(suid_fd);
	fclose(sgid_fd);
	fclose(writeable_fd);
	fclose(unowned_user_fd);
	fclose(unowned_group_fd);

        exit(res);
}






