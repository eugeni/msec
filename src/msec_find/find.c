/*
 * Written by Thierry Vignaud,
 * heavilly modified for msec purpose by Vandoorselaere Yoann.
 *
 * This code is copyrighted by Mandrakesoft [(c) 2000] and is released under
 *  the GPL licence
 */


/*
 * TODO
 * +++  hash tables or btree to stock already searched uid/gid for speed
 *              Pb: since linux-2.3.4x, uid & gid are 32 bits wide ... => BTREE?
 *              static char **uid_hash, **gid_hash;
 *
 * +++  check for open & I/O error on log files ...
 * +++  Yoann scripts should avoid /dev if devfs is mounted (either by testing
 *              if /dev is mounted by devfs or if [ -f /dev/.devfsd ] => see with
 *              Yoann
 * ---  disable 'cannot stat ...' warning (???) => better log them SECURITY_LOG
 * ---  disable write test on links => OK
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
#include <regex.h>

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
static FILE *writable_fd;
static regex_t exclude_regexp;
static int use_regexp = 0;

static int traverse(const char *file, const struct stat *sb, int flag, struct FTW *s)
{
        struct passwd *u_nss_data;
        struct group *g_nss_data;

         /*
          * handle bogus glibc ftw
          * else we won't print only one '/' in front of file names
          */
	if (strncmp(file, "//", 2) == 0 )
                file++;

        /*
         * Don't walk throught /dev & /proc
         */
        if ( (strncmp("/proc", file, 5) == 0) || (strncmp("/dev", file, 4) == 0) )
                return 0;

        if (use_regexp && regexec(&exclude_regexp, file, 0, NULL, 0) == 0) {
		return 0;
	}
	
	switch (flag) {
                /*
                 * Regular file handling.
                 */
        case FTW_F:
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

                /*
                 * Their is no break statement here, it is normal.
                 * Directory handing.
                 */
        case FTW_D:
                /*
                 * Is world writable check.
                 */
		if (sb->st_mode & 0002)
			fprintf(writable_fd, "%s\n", file);
                
                /*
                 * Unowned user check.
                 */
		u_nss_data = getpwuid(sb->st_uid);
		if (u_nss_data == NULL)
			fprintf(unowned_user_fd, "%s\n", file);

                /*
                 * Unowned group check.
                 */
                g_nss_data = getgrgid(sb->st_gid);
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
	char *env;

        suid_fd = fopen(getenv("SUID_ROOT_TODAY"), mode);
        if ( ! suid_fd ) {
                perror("fopen (suid_root_today)");
                exit(1);
        }
        
        sgid_fd = fopen(getenv("SGID_TODAY"), mode);
        if ( ! sgid_fd ) {
                perror("fopen (sgid_today)");
                exit(1);
        }

        writable_fd = fopen(getenv("WRITABLE_TODAY"), mode);
        if ( ! writable_fd ) {
                perror("fopen (writable_today)");
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
	
	env = getenv("EXCLUDE_REGEXP");
	if (env) {
		if (regcomp(&exclude_regexp, env, 0) == 0) {
			use_regexp = 1;
		} else {
			fprintf(stderr, "Unable to compile EXCLUDE_REGEXP '%s'\n", env);
			exit(1);
		}
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

        for ( i = 1; i < argc; i++ ) {
                if ( strcmp(argv[i], "/") != 0) {
                        /*
                         * We need to add a final '/' to the base directory name else the
                         * FTW_MOUNT option of nftw won't work. i.e. : /mnt/cdrom is on the /
                         * fs (it is the directory on which a CD is mounted) whereas
                         * /mnt/cdrom/ is the mounted directory.
                         * Hopefully, find has the same "bug"
                         */
                    
                        ctrl = 1;
                        directory = ( char * ) malloc((strlen(argv[i]) + 2));
                        if ( ! directory ) {
                                perror("malloc");
                                exit(1);
                        }
                        
                        strcpy(directory, argv[i]);
                        strcat(directory, "/");
                } else {
		        directory = argv[i];
		}

		res = nftw(directory, traverse, 200, FTW_PHYS | FTW_MOUNT);
		
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
	fclose(writable_fd);
	fclose(unowned_user_fd);
	fclose(unowned_group_fd);

        exit(res);
}







