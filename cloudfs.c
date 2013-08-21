#define _XOPEN_SOURCE 501
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <openssl/md5.h>
#include <time.h>
#include <unistd.h>
#include "cloudapi.h"
#include "cloudfs.h"
#include "dedup.h"
#include <errno.h>

#define UNUSED __attribute__((unused))
int avg_seg_size = 4096;
int min_seg_size = 1024;
int max_seg_size = 16384;
int window_size = 36;
int segmentation = 0;
int in_dirty = 0; 
int g_in_ssd = 0;
int g_in_cloud = 0;
int g_metafile_length = 0;
off_t g_size = 0;
off_t global_lru =0;
char g_fpath[PATH_MAX];
off_t current_cache_size = 0;
int implement_cache=1;
off_t total_cache_size = 2048*1024;
off_t max_lru = 0;
int exceeded_cache_size = 0;
FILE *logfile;

/* Global Lookup/Hash Table
 * It is used to implement deduplication
 */
typedef struct lookup lookup;
struct lookup
{
  lookup *next;
  char hash[(MD5_DIGEST_LENGTH*2)+1];
  int segment_len;
  int reference_count;
};
lookup hashtable[256]; 

typedef struct copy_on_write cow;
struct copy_on_write
{
  cow *next;
  char hash[(MD5_DIGEST_LENGTH*2)+1];
  int segment_len;
  int found;
};
cow *cow_head = NULL;

/*Doubly linked list used for Segment to file mapping*/
typedef struct mapping file_mapping;
struct mapping
{
  file_mapping *next;
  char hash[(MD5_DIGEST_LENGTH*2)+1];
  int segment_len;
};

/*Singly linked list used to keep track of cache contents*/
typedef struct list cache_list;
struct list
{
  char name[PATH_MAX];
  cache_list *next;
  cache_list *prev;
  off_t size;
  off_t cost;
};
cache_list *cache_head, *cache_tail;

static struct cloudfs_state state_;
void cloudfs_read_lookuptxt(FILE *fh);
void cloudfs_initialize_lookup();
int cloudfs_unlink_metafile(char *fpath);
int convert_name(char *fpath, char *cpath);
int put_segment(char *buffer, int bufferLength);
int get_segment(const char *buffer, int bufferLength);
void cloudfs_segmentation(char *path, int argument);
void cloudfs_update_linked_list_map( int segment_len, char *name, file_mapping **head, file_mapping **tail, int *size);
void cloudfs_load_infileDS(file_mapping **head, file_mapping **tail, char *sbuf);
void cloudfs_read_metafile(int metafile_length, char *fpath, off_t filesize, int populate_file);
void cloudfs_populate_put_segment(FILE *fp, int segment_len, int read_offset, char *name);
int cloudfs_search_lookup(char *md5, char *name, int segment_len);
void cloudfs_clear_linked_list(file_mapping *head);
void cloudfs_delete_records(char *sbuf);
void cloudfs_reduce_count(char *hash);
void cloudfs_populate_metafile(int size, char *fpath, int *metafile_length, file_mapping **head, file_mapping **tail);
void cloudfs_retrieving_data(char *fpath, char *sbuf, off_t file_size);
void cloudfs_convert_filename(char *fpath, char *metapath);
void cloudfs_clean_cloud();
int cache_open(const char *path, struct fuse_file_info *f1);
int cache_deconvert_name(char *cpath, char *fpath);
int cache_dir_list_initialization();
int cache_build_linked_list(DIR *fp);
int cache_release(const char *path, struct fuse_file_info *fi);
int cache_add_list(char *fpath);
int cache_add(char *fpath);
int cache_delete(char *fpath);
int cache_delete_list(char *fpath);
int cache_eviction(off_t required_size);
int cache_evict_cloud(char *fpath);
int cache_unlink(const char *fpath);
int cache_addbuild_list(off_t cost, char *fpath, off_t filesize);
void cache_clear_list();
void cloudfs_cow_delete(int metafile_length, char *fpath, off_t filesize, file_mapping *head);
void cow_delete();

static int UNUSED cloudfs_error(char *error_str)
{
    int retval = -errno;
    fprintf(stderr, "CloudFS Error: %s\n", error_str);
    /* FUSE always returns -errno to caller (yes, it is negative errno!) */
    return retval;
}

/*
 * cloudfs_init
 * Initializes the FUSE file system (cloudfs) by checking if the mount points
 * are valid, and if all is well, it mounts the file system ready for usage.
 *
 */
void *cloudfs_init(struct fuse_conn_info *conn UNUSED)
{
  fprintf(logfile, "init\n");
  fflush(logfile);
  cloud_init(state_.hostname);

  segmentation = state_.no_dedup;
  window_size = state_.rabin_window_size;
  avg_seg_size = state_.avg_seg_size;
  min_seg_size = avg_seg_size / 4;
  max_seg_size = avg_seg_size * 4;
  total_cache_size = state_.cache_size;
  implement_cache = !state_.no_cache;

  char mypath[PATH_MAX];
  char lookup_path[PATH_MAX] = ".lookup";
  strcpy(mypath, state_.ssd_path);
  strcat(mypath, lookup_path);

  cloud_create_bucket("bucket");
  /*If Cache is implemented*/
  if(implement_cache == 1)
    cache_dir_list_initialization();

  /*If segmentation of file is used*/
  if(segmentation == 0)
  {
    FILE *fh;
    fh = fopen(mypath, "rb");

	/*Initializes the global hash table during first run*/
    if(fh == NULL)
    {
      printf("Initializing lookup\n");
      cloudfs_initialize_lookup();
    }
	/*Reads from the persistent .lookup file for subsequent runs*/
    else
    {
      printf("read lookup\n");
      cloudfs_read_lookuptxt(fh);
      fclose(fh);
    }
  }
  return NULL;
}

/*
 * cache_dir_list_initialization:
 * This function does the following:
 * 1) Checks if the dir exists, if not call mkdir 
 * 2) Build linkedlist by running through the .cache dir
 */
int cache_dir_list_initialization()
{
  fprintf(logfile,"dir_list_initialization\n");
  fflush(logfile);
  
  DIR *dp;
  char fpath[PATH_MAX];
  strcpy(fpath, state_.ssd_path);
  strcat(fpath, ".cache");
  dp = opendir(fpath);
  int retstat = 0;

  /* If cache does not exist create a directory
   * in SSD called .cache to store cache content */
  if (dp == NULL)
  {
    cache_head = NULL;
    cache_tail = NULL;
    retstat = mkdir(fpath, 0777);
    if(retstat < 0)
    {
      printf("My mkdir error\n");
      return retstat;
    }
  }

  /* If cache already exists run through the .cache
   * directory and build the linked list */
  else
  {
    cache_build_linked_list(dp);
    closedir(dp);  
  }
  return retstat;
}

/*
 * cache_build_linked_list
 * This function does the following
 * 1) It builds the in-memory linkedlist by running through .cache dir
 * 2) Sets the global variables like LRU and current_cache_size
 */
int cache_build_linked_list(DIR *dp)
{
  fprintf(logfile,"build_linked_list\n");
  fflush(logfile);
  
  int retstat = 0;
  off_t lru = 0;
  struct dirent *de;
  char fpath[PATH_MAX];
  cache_head = NULL;
  cache_tail = NULL;
  de = readdir(dp);

  if(de == 0)
  {
    retstat = cloudfs_error("cloudfserror readdir");
    return retstat;
  }

  /* Runs through the .cache directory and build the list
   * with all elements in cache
   */ 
  do
  {
	/*To ignore the current and parent directory entries*/
    if((strcmp(de->d_name,".")==0) || (strcmp(de->d_name,"..")==0))
      continue;

    cache_deconvert_name(de->d_name, fpath);
    lgetxattr(fpath,"user.LRU", &lru, sizeof(off_t));
    global_lru = lru;
  
	char cache_path[PATH_MAX];
    char cache[]=".cache/";
    strcpy(cache_path, state_.ssd_path);
    strcat(cache_path, cache);
    strcat(cache_path, de->d_name);

    struct stat stat_buf;
    lstat(cache_path, &stat_buf);

    cache_addbuild_list(global_lru, fpath, stat_buf.st_size);
  }
  while((de = readdir(dp))!=NULL);
  fprintf(logfile,"leaving_build_linked_list\n");
  fflush(logfile);
  return retstat;
}

/*
 * cache_addbuild_list
 * It adds a new element into the linked list as and when new item
 * is added to cash, the linked list is ordered in increasing order of size
 * so as to evict the biggest element into cloud to reduce costs
 */
int cache_addbuild_list(off_t cost, char *fpath, off_t filesize)
{
  fprintf(logfile,"add_build_list\n");
  fflush(logfile);
  int retstat = 0;
  cache_list *current;
  current = cache_head;
  
  current_cache_size = current_cache_size + filesize;
  if(cost > max_lru)
    max_lru = cost;
  
  if(current == NULL)
  {
    cache_list *temp = (cache_list *)malloc(sizeof(cache_list));
    strcpy(temp->name, fpath);
    temp->size = filesize;
    temp->cost = cost;
    temp->prev = NULL;
    temp->next = cache_head;
    cache_tail = temp;
    cache_head = temp;
    return retstat;
  }
  else
  {
    while(current!=NULL)
    {
      if(cost > current->cost)
      {
        cache_list *temp = (cache_list *)malloc(sizeof(cache_list));
        strcpy(temp->name, fpath);
        temp->size = filesize;
        temp->cost = cost;
        temp->next = current;
        temp->prev = current->prev;
        if(current == cache_head)
          cache_head = current;
        else
          temp->prev->next = temp;
        current->prev = temp;
        return retstat;
      }
      current = current->next;
    }
    cache_list *temp = (cache_list *)malloc(sizeof(cache_list));
    strcpy(temp->name, fpath);
    temp->size = filesize;
    temp->cost = cost;
    temp->next = NULL;
    temp->prev = cache_tail;
    cache_tail->next = temp;
    cache_tail = temp;
  }
  return retstat;
}

/*
 * cloudfs_read_lookuptxt
 * Build the global hash table from the persistent file
 * Required to make cloud storage persistent
 */
void cloudfs_read_lookuptxt(FILE *fh)
{
  fprintf(logfile, "read_lookuptxt");
  fflush(logfile);
  int num = 0;
  lookup hash_entry;
  const char empty[]="empty";

  while(num<=255)
  { 
    int i = 0;
    int cont = 1;
    lookup *previous = NULL;
    while(cont == 1)
    {
      if(fscanf(fh, "%s %d %d ", hash_entry.hash, &hash_entry.reference_count, &hash_entry.segment_len) != 3)
       return;
      if(strcmp(hash_entry.hash, empty)==0 && i == 0 && hash_entry.reference_count == 0)
      {
        strcpy(hashtable[num].hash, empty);
        hashtable[num].reference_count = hash_entry.reference_count;
        hashtable[num].segment_len = hash_entry.segment_len;
        hashtable[num].next = NULL;
        num++;
        cont = 0;
      }

      else if(strcmp(hash_entry.hash, empty)!=0 && i == 0)
      {
        i++;
        strcpy(hashtable[num].hash, hash_entry.hash);
        hashtable[num].reference_count = hash_entry.reference_count;
        hashtable[num].segment_len = hash_entry.segment_len;
        hashtable[num].next = NULL;
      }

      else if(strcmp(hash_entry.hash, empty)==0 && i == 1 && hash_entry.reference_count == 0)
      {
        num++;
        cont = 0;
      }

      else if(strcmp(hash_entry.hash, empty)!=0 && i == 1)
      {
        lookup *current = (lookup *)malloc(sizeof(lookup));
        previous = current;
        strcpy(current->hash, hash_entry.hash);
        current->reference_count = hash_entry.reference_count;
        current->segment_len = hash_entry.segment_len;
        current->next = NULL;
        hashtable[num].next = current;
        i++;
      }

      else if(strcmp(hash_entry.hash, empty)==0 && i > 1 && hash_entry.reference_count == 0)
      {
        num++;
        cont = 0;
      }

      else if(strcmp(hash_entry.hash, empty)!=0 && i > 1)
      {
        lookup *current = (lookup *)malloc(sizeof(lookup));
        strcpy(current->hash, hash_entry.hash);
        current->reference_count = hash_entry.reference_count;
        current->segment_len = hash_entry.segment_len;
        current->next = NULL;
        previous->next = current;
        previous = current;
        i++;
      }
    }
  }
}

/*
 * cloudfs_initialize_lookup
 * Initialize the global lookup table on the first tun
 */
void cloudfs_initialize_lookup()
{

  fprintf(logfile, "initilialize lookup");
  fflush(logfile);
  int i;
  const char empty[]="empty";
  /*Set all the entries to null*/
  for (i=0; i<=255; i++)
  {
    hashtable[i].reference_count = 0;
    hashtable[i].next = NULL;
    hashtable[i].segment_len = 0;
    strcpy(hashtable[i].hash,empty);
  }
}

int list_bucket(const char *key, time_t modified_time, uint64_t size) {
  fprintf(stdout, "%s %lu %llu\n", key, modified_time, size);
  return 0;
}

int list_service(const char *bucketName) {
  fprintf(stdout, "%s\n", bucketName);
  return 0; 
}

static FILE *outfile;
int get_buffer(const char *buffer, int bufferLength) {
  printf("Inside get_buffer \n");
  return fwrite(buffer, 1, bufferLength, outfile);  
}

static FILE *infile;
int put_buffer(char *buffer, int bufferLength) {
  fprintf(stdout, "put_buffer %d \n", bufferLength);
  return fread(buffer, 1, bufferLength, infile);
}

int cloudfs_getattr(const char *path, struct stat *statbuf)
{
    fprintf(logfile, "getattr");
    fflush(logfile);
    int retstat = 0, count;
    char fpath[PATH_MAX];
    strcpy(fpath, state_.ssd_path);
    strcat(fpath, path);
    int in_cloud = 0;
    int in_ssd = 0;
    off_t size;
    
    lgetxattr(fpath,"user.IN_CLOUD", &in_cloud, sizeof(int));
    lgetxattr(fpath,"user.IN_SSD", &in_ssd, sizeof(int));
    retstat = lstat(fpath, statbuf);
   
    if(in_cloud == 1 || in_ssd == 1)
    {
      lgetxattr(fpath,"user.SIZE_CLOUD", &size, sizeof(off_t));
      statbuf->st_size = size;
    }
    if (retstat < 0) 
    {
     retstat = cloudfs_error("getattr error");
    }
    return retstat;
}

int cloudfs_mkdir(const char *path, mode_t mode)
{
  fprintf(logfile, "mkdir");
  fflush(logfile);
  int retstat = 0;
  char fpath[PATH_MAX];
  strcpy(fpath, state_.ssd_path);
  strcat(fpath, path);

  retstat = mkdir(fpath, mode);
  if (retstat < 0)
    retstat = cloudfs_error("cloudfs_error mkdir");
  printf("Making directory\n");
  return retstat;
}

int cloudfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
  fprintf(logfile, "readdir\n");
  fflush(logfile);
  int retstat = 0;
  DIR *dp;
  struct dirent *de;
  
  dp = (DIR *) (uintptr_t) fi->fh;
  de = readdir(dp);
  
  if(de == 0)
  {
    retstat = cloudfs_error("cloudfserror readdir");
    return retstat;
  }
  do
  {
    if(de->d_name[0]!='.')
    {
      if(filler(buf, de->d_name, NULL, 0)!=0)
        return -ENOMEM;
    }
  }
  while((de = readdir(dp))!=NULL);
  return retstat;
}

/*
 * cloudfs_destroy:
 * 1)It writes the lookup table to a file => .lookup.txt
 * 2)It writes the linked list to a file => .metacache.txt
 */
void cloudfs_destroy(void *data) {
  fprintf(logfile, "destroy");
  fflush(logfile);
  printf("destroy\n");
  if(segmentation == 0)
    cloudfs_clean_cloud();
  if(implement_cache == 1)
    cache_clear_list();
  cloud_destroy();
}

void cache_clear_list()
{
  fprintf(logfile, "clear_list");
  fflush(logfile);
  cache_list *current, *previous;
  current = cache_head;
  while(current != NULL)
  {
    previous = current;
    current = current->next;
    free(previous);
  }
}

/*
 * cloudfs_clean_cloud
 * 1)Builds the persistant file(.lookup) from the global lookup table
 */
void cloudfs_clean_cloud()
{
  fprintf(logfile, "clean_cloud");
  fflush(logfile);
  const char empty[] = "empty"; 
  int num = 0;
  
  char mypath[PATH_MAX];
  char lookup_path[PATH_MAX] = "/.lookup";
  strcpy(mypath, state_.ssd_path);
  strcat(mypath, lookup_path);
  
  FILE *lookup_fd;
  
  lookup_fd = fopen(mypath, "w+");
  lookup hash_entry;

  
  /*Runs through the global hash table and writes to persistent
   *file only if reference count >=1
   */
  while(num<=255)
  {
    if(strcmp(hashtable[num].hash, empty)==0)
    {
      strcpy(hash_entry.hash, empty);
      hash_entry.reference_count  = 0;
      hash_entry.segment_len = 0; 
      printf("%s %d %d ", hash_entry.hash, hash_entry.reference_count, hash_entry.segment_len);   
      fprintf(lookup_fd, "%s %d %d ", hash_entry.hash, hash_entry.reference_count, hash_entry.segment_len);   
    }
    else
    {
      if(hashtable[num].next == NULL)
      {
        if(hashtable[num].reference_count == 0 && strcmp(hashtable[num].hash, empty)!=0)
        else
        {
          strcpy(hash_entry.hash, hashtable[num].hash);
          hash_entry.reference_count  = hashtable[num].reference_count;
          hash_entry.segment_len = hashtable[num].segment_len; 
          printf("%s %d %d ", hash_entry.hash, hash_entry.reference_count, hash_entry.segment_len);   
          fprintf(lookup_fd, "%s %d %d ", hash_entry.hash, hash_entry.reference_count, hash_entry.segment_len);   
        }
        
        strcpy(hash_entry.hash, empty);
        hash_entry.reference_count  = 0;  
        hash_entry.segment_len = 0; 
        printf("%s %d %d ", hash_entry.hash, hash_entry.reference_count, hash_entry.segment_len);   
        fprintf(lookup_fd, "%s %d %d ", hash_entry.hash, hash_entry.reference_count, hash_entry.segment_len);   
      }
      else
      {
        if(hashtable[num].reference_count == 0 && strcmp(hashtable[num].hash, empty)!=0)
        else
        {
          strcpy(hash_entry.hash, hashtable[num].hash);
          hash_entry.reference_count  = hashtable[num].reference_count;
          hash_entry.segment_len = hashtable[num].segment_len; 
          printf("%s %d %d ", hash_entry.hash, hash_entry.reference_count, hash_entry.segment_len);   
          fprintf(lookup_fd, "%s %d %d ", hash_entry.hash, hash_entry.reference_count, hash_entry.segment_len);   
        }

        lookup *current = hashtable[num].next;
        lookup *previous;
        while(current!=NULL)
        {
          if(current->reference_count == 0 && strcmp(current->hash, empty)!=0)
          else
          {
            strcpy(hash_entry.hash, current->hash);
            hash_entry.reference_count  = current->reference_count;
            hash_entry.segment_len = current->segment_len; 
            printf("%s %d %d ", hash_entry.hash, hash_entry.reference_count, hash_entry.segment_len);   
            fprintf(lookup_fd, "%s %d %d ", hash_entry.hash, hash_entry.reference_count, hash_entry.segment_len);   
          }
          previous = current;
          current = current->next;
          free(previous);
        }

        strcpy(hash_entry.hash, empty);
        hash_entry.reference_count  = 0;  
        hash_entry.segment_len = 0; 
        printf("%s %d %d ", hash_entry.hash, hash_entry.reference_count, hash_entry.segment_len);   
        fprintf(lookup_fd, "%s %d %d ", hash_entry.hash, hash_entry.reference_count, hash_entry.segment_len);   
      }
    }
    num++;
  }
  fclose(lookup_fd);
}

int cloudfs_readlink(const char *path, char *link, size_t size)
{
  printf("readlink\n");
  return 0;
}

int cloudfs_mknod(const char *path, mode_t mode, dev_t dev)
{
    fprintf(logfile, "mknod");
    fflush(logfile);
    int retstat = 0;
    char fpath[PATH_MAX];
    strcpy(fpath, state_.ssd_path);

    strcat(fpath, path);
    printf("mknod");
    int in_cloud = 0; 
    off_t lru = 0;
    off_t size_cloud = 0;
    int dirty_cloud = 0;
    int metasize = 0;
    int in_ssd =0;

	/*Sets all the attributes of the file so that we can use it to keep
	 *in track of the files presence even if truncated and put in cloud
	 */
    lsetxattr(fpath, "user.METASIZE_CLOUD", &metasize, sizeof(int), 0 );
    lsetxattr(fpath, "user.LRU", &lru, sizeof(off_t), 0 );
    lsetxattr(fpath, "user.IN_SSD", &in_ssd, sizeof(int), 0 );
    lsetxattr(fpath, "user.IN_CLOUD", &in_cloud, sizeof(int), 0 );
    lsetxattr(fpath, "user.SIZE_CLOUD", &size_cloud, sizeof(off_t), 0);
    lsetxattr(fpath, "user.DIRTY_CLOUD", &dirty_cloud, sizeof(int), 0);
    
    if (S_ISREG(mode)) {
        retstat = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
	if (retstat < 0)
	    retstat = cloudfs_error("cloudfs_mknod open");
        else {
            retstat = close(retstat);
	    if (retstat < 0)
		retstat = cloudfs_error("cloudfs_mknod close");
	}
    } else
	if (S_ISFIFO(mode)) {
	    retstat = mkfifo(fpath, mode);
	    if (retstat < 0)
		retstat = cloudfs_error("cloudfs_mknod mkfifo");
	} else {
	    retstat = mknod(fpath, mode, dev);
	    if (retstat < 0)
		retstat = cloudfs_error("cloudfs_mknod mknod");
	}
    return retstat;
}

/*
 * cloudfs_unlink
 * This function is used to delete the file and clears all stored data structures
 * and file whether its present in the SSD or the cloud
 */
int cloudfs_unlink(const char *path){
  fprintf(logfile, "cloudfs_unlink for %s\n", path);
  fflush(logfile);
  int retstat = 0;
  char fpath[PATH_MAX];
  strcpy(fpath, state_.ssd_path);
  strcat(fpath,path);
  int in_cloud=0;
  int in_ssd=0;
  off_t size;
  int metasize = 0;

  
  int i = 0;
  int position = 0;

  char *current_path = fpath;

  while(current_path[i]!='\0')
  {
    if(current_path[i]=='/')
      position = i;
    i++;
  }
  position++;

  if(current_path[position] == '.')
    return 0; 

  lgetxattr(fpath,"user.IN_CLOUD", &in_cloud, sizeof(int));
  lgetxattr(fpath,"user.IN_SSD", &in_ssd, sizeof(int));
  lgetxattr(fpath,"user.SIZE_CLOUD", &size, sizeof(off_t));
  lgetxattr(fpath,"user.METASIZE_CLOUD", &metasize, sizeof(int));
  
  if(implement_cache == 1 && in_ssd == 1)
  {
    cache_delete(fpath);
    cache_delete_list(fpath);
  }

  if(segmentation == 0 && size > state_.threshold  && in_cloud ==1 )
  {
    if(metasize != 0)
    {
      cloudfs_read_metafile(metasize, fpath, size, 0);
      cloudfs_unlink_metafile(fpath);
      /*Listing the objects in the cloud after deletion
	   *for debugging purposes
	   */
	  cloud_list_bucket("bucket", list_bucket);
    }
    in_cloud = 0;
    lsetxattr(fpath,"user.IN_CLOUD", &in_cloud, sizeof(int),0);
  }

  if(size > state_.threshold && in_cloud == 1 && segmentation == 1)
  {
    char *cpath = (char *)malloc(PATH_MAX);
    convert_name(fpath, cpath);
    cloud_delete_object("bucket",cpath);
      
    cloud_list_bucket("bucket", list_bucket);
    
    free(cpath);
    in_cloud = 0;
    lsetxattr(fpath,"user.IN_CLOUD", &in_cloud, sizeof(int),0);
  }
  retstat = unlink(fpath);
  if(retstat < 0)
    retstat = cloudfs_error("unlink error");
  printf("unlink\n");
  return retstat;
}

int cloudfs_rmdir(const char *path)
{
  int retstat = 0;
  char fpath[PATH_MAX];
  strcpy(fpath, state_.ssd_path);
  strcat(fpath, path);

  retstat = rmdir(fpath);
  if(retstat < 0)
    retstat = cloudfs_error("rmdir error");
  printf("rmdir\n");
  return retstat;
}

int cloudfs_symlink(const char *path, const char *link)
{
  int retstat = 0;
  printf("symlink\n");
  return retstat;
}

int cloudfs_rename(const char *path, const char *newpath)
{
  int retstat = 0;
  char fpath[PATH_MAX];
  strcpy(fpath, state_.ssd_path);
  char fnewpath[PATH_MAX];
  strcpy(fnewpath, state_.ssd_path);
  strcat(fpath, path);
  strcat(fnewpath, newpath);

  retstat = rename(fpath, fnewpath);
  if(retstat < 0)
    retstat = cloudfs_error("rename error");
  printf("rename\n");
  return retstat;
}

int cloudfs_link(const char *path, const char *newpath)
{
  printf("link\n");
  return 0;
}

int cloudfs_chmod(const char *path, mode_t mode)
{
  int retstat = 0;
  char fpath[PATH_MAX];
  strcpy(fpath, state_.ssd_path);
  strcat(fpath, path);
  
  retstat = chmod(fpath, mode);
  if (retstat < 0)
    retstat = cloudfs_error("error chmod");
  printf("chmod\n");
  return retstat;
}

int cloudfs_chown(const char *path, uid_t uid, gid_t gid)
{
  int retstat = 0;
  char fpath[PATH_MAX];
  strcpy(fpath, state_.ssd_path);
  strcat(fpath, path);

  retstat = chown(fpath, uid, gid);
  if (retstat < 0)
    retstat = cloudfs_error("error chown");
  printf("chown\n");
  return retstat;
}

int cloudfs_truncate(const char *path, off_t newsize)
{
  int retstat = 0;
  char fpath[PATH_MAX];
  strcpy(fpath, state_.ssd_path);
  strcat(fpath, path);

  retstat = truncate(fpath, newsize);
  if(retstat < 0)
    retstat = cloudfs_error("error truncate");
  printf("truncate\n");
  return retstat;
}

int cloudfs_utime(const char *path, struct utimbuf *ubuf)
{
  int retstat = 0;
  char fpath[PATH_MAX];
  strcpy(fpath, state_.ssd_path);
  strcat(fpath, path);

  retstat = utime(fpath, ubuf);
  if (retstat < 0)
    retstat = cloudfs_error("error utime");
  printf("utime\n");
  return retstat;
}

/*
 * cache_open
 * Opens the file whether it is stored on the cloud or SSD
 * and increments the LRU count of the file
 */
int cache_open(const char *path, struct fuse_file_info *fi)
{
  fprintf(logfile, "cache_open\n");
  fflush(logfile);
  int retstat = 0;
  int metasize = 0;
  int fd, in_cloud=0, in_ssd=0;
  FILE *cache_desc;
  struct stat stat_buf;
  off_t size;

  char fpath[PATH_MAX];
  strcpy(fpath, state_.ssd_path);
  strcat(fpath, path);
  
  fd = open(fpath, fi->flags);
  if(fd<0)
    retstat = cloudfs_error("open error");

  fi->fh = fd;
  
  lgetxattr(fpath,"user.IN_CLOUD", &in_cloud, sizeof(int));
  lgetxattr(fpath,"user.SIZE_CLOUD", &size, sizeof(off_t));
  lgetxattr(fpath,"user.METASIZE_CLOUD", &metasize, sizeof(int));
  lgetxattr(fpath,"user.IN_SSD", &in_ssd, sizeof(int));
  
  /*Increments the LRU count of the most recently used object*/
  max_lru = max_lru + 1;
  lsetxattr(fpath,"user.LRU", &max_lru, sizeof(off_t), 0);
  
  g_in_cloud = in_cloud;
  g_size = size;
  g_metafile_length = metasize;
  g_in_ssd = in_ssd;

  /*Object is in cache*/
  if(in_ssd == 1)
  {
    fprintf(logfile, "The file %s is read from ssd\n", fpath);
    char cpath[PATH_MAX];
    convert_name(fpath, cpath);
    FILE *file_fp;

    char cache_path[PATH_MAX];
    char cache[]=".cache/";
    strcpy(cache_path, state_.ssd_path);
    strcat(cache_path, cache);
    strcat(cache_path, cpath);
    fflush(logfile);
    
    file_fp = fopen(fpath, "wb+");
    cache_desc = fopen(cache_path, "rb+");
   
    lstat(cache_path, &stat_buf);

    char buf[1024];
    size_t return_size;
    while((return_size = fread(buf, 1, 1024,  cache_desc))>0)
     fwrite(buf, 1, return_size, file_fp);
    fclose(cache_desc);
    fclose(file_fp);
  }

  /*Object is in cloud and segmentation is used*/
  if(in_cloud == 1 && segmentation == 0)
  {
    if(metasize !=0 )
    {
      fprintf(logfile, "The file %s is read from cloud \n", fpath);
      cloudfs_read_metafile(metasize, fpath, size, 1);
    }
  }

  /*Object is in cloud and segmentation is not used*/
  if(in_cloud == 1 && segmentation == 1)
  {
    char *cpath = (char *)malloc(PATH_MAX);
    convert_name(fpath, cpath);
    outfile = fopen(fpath, "wb");
    printf("Getting object from the cloud \n");
    cloud_get_object("bucket", cpath, get_buffer);
    fclose(outfile);
    free(cpath);
  }

  in_dirty = 0;
  return retstat;
}

/*
 * cloudfs_open
 * This handles the open operation only if cache is not used
 */
int cloudfs_open(const char *path, struct fuse_file_info *fi)
{
  int retstat = 0;
  if(implement_cache == 1)
  {
    cache_open(path, fi);
    return retstat;
  }

  int metasize = 0;
  int fd, in_cloud=0;
  char fpath[PATH_MAX];
  strcpy(fpath, state_.ssd_path);
  strcat(fpath, path);
  struct stat stat_buf;
  off_t size;
  
  fd = open(fpath, fi->flags);
  if(fd<0)
    retstat = cloudfs_error("open error");

  fi->fh = fd;

  lstat(fpath, &stat_buf);
  lgetxattr(fpath,"user.IN_CLOUD", &in_cloud, sizeof(int));
  lgetxattr(fpath,"user.SIZE_CLOUD", &size, sizeof(off_t));
  lgetxattr(fpath,"user.METASIZE_CLOUD", &metasize, sizeof(int));
  
  g_in_cloud = in_cloud;
  g_metafile_length = metasize;
  g_size = size;
 
  /*Object is in cloud and segmentation is used*/
  if(segmentation == 0 && size > state_.threshold && in_cloud == 1)
  {
    if(metasize !=0 )
    {
      printf("The metafile size during a read operations is %d\n", metasize);
      cloudfs_read_metafile(metasize, fpath, size, 1);
    }
  }
  
  /*Object is in cloud but segmentation is not used*/
  if(size > state_.threshold && in_cloud == 1 && segmentation == 1)
  {
    char *cpath = (char *)malloc(PATH_MAX);
    convert_name(fpath, cpath);
    outfile = fopen(fpath, "wb");
    printf("Getting object from the cloud \n");
    cloud_get_object("bucket", cpath, get_buffer);
    fclose(outfile);
    free(cpath);
  }

  /*
   * Resetting the dirty bit so that it will be deleted and written back only
   * if the dirty bit is set as a consequence of the write operation
   */
  in_dirty = 0;

  printf("open\n");
  return retstat;
}

/*
 * cloudfs_write
 * 1) Writes into the file
 * 2) The dirty bit is set
 */
int cloudfs_write(const char *path, const char *buf, size_t size, off_t offset,
	     struct fuse_file_info *fi)
{
  fprintf(logfile, "cloudfs_write\n");
  fflush(logfile);
  char fpath[PATH_MAX];
  strcpy(fpath, state_.ssd_path);
  strcat(fpath, path);
  strcpy(g_fpath, fpath);

  int retstat = 0;
  off_t filesize = 0;
  int in_ssd = g_in_ssd;
  int in_cloud = g_in_cloud;

  printf("The in_cloud in write is %d\n", in_cloud);

  lgetxattr(fpath,"user.SIZE_CLOUD", &filesize, sizeof(off_t));

  retstat = pwrite(fi->fh, buf, size, offset);
  /*The dirty bit has been set*/
  in_dirty = 1;

  if(retstat < 0)
    retstat = cloudfs_error("error write");
  return retstat;
}

int cloudfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
  fprintf(logfile, "cloudfs_read\n");
  fflush(logfile);
  int retstat = 0;
  retstat = pread(fi->fh, buf, size, offset);
  if (retstat < 0)
    retstat = cloudfs_error("read error");
  fprintf(logfile, "read of %s\n with offset %lu", path, offset);
  fflush(logfile);
  return retstat;
}

int cloudfs_statfs(const char *path, struct statvfs *statv)
{
  int retstat = 0;
  char fpath[PATH_MAX];
  strcpy(fpath, state_.ssd_path);
  strcat(fpath, path);

  retstat = statvfs(fpath, statv);
  if(retstat < 0)
    retstat = cloudfs_error("statfs error");
  printf("statfs\n");
  return retstat;
}

int cloudfs_flush(const char *path, struct fuse_file_info *fi)
{
  int retstat = 0;
  printf("flush\n");
  return retstat;
}

/*convert_name
 *Stores the same file by substituting '/' with '+'
 *this is done to follow amazon ec2 standards
 */
int convert_name(char *fpath, char *cpath)
{
  int i;
  strcpy(cpath, fpath);
  int len = strlen(cpath);
  printf("The cpath in convertname is %s\n", cpath);
  printf("The len in convertname is %d\n", len);
  for(i = 0; i< len; i++)
  {
    if(cpath[i] == '/')
    {
      cpath[i]='+';
      printf("The cpath in convertname is %s\n", cpath);
    }
  }
  return 0;
}

/*
 * deconvertname
 * change the name again from the one stored on the cloud to the actual name
 * while retrieving
 */
int cache_deconvert_name(char *cpath, char *fpath)
{
  int i;
  strcpy(fpath, cpath);
  int len = strlen(fpath);
  for(i = 0; i< len; i++)
  {
    if(fpath[i] == '+')
      fpath[i]='/';
  }
  return 0;
}

char *inbuf;
/* 
 * put_segment
 * Puts the segment in the cloudi
 */
int put_segment(char *buffer, int bufferLength)
{
  fprintf(stdout, "put_segment %d \n", bufferLength);
  memcpy(buffer, inbuf, bufferLength);
  return bufferLength;
}

char *outbuf=NULL;

/* 
 * get_segment
 * gets the segement from the cloud
 */
int get_segment(const char *buffer, int bufferLength)
{
  printf("Get segment %d\n", bufferLength);
  memcpy(outbuf, buffer, bufferLength); 
  outbuf = outbuf + bufferLength;
  return bufferLength;
}

/* 
 * cloudfs_populate_put_segment
 * reads the segment names from the in-file data structures
 * which store the file to segment mappings and uses these to 
 * put the segments
 */
void cloudfs_populate_put_segment(FILE *infile, int segment_len, int read_offset, char *name)
{
  fprintf(logfile, "populate_put_Segment\n");
  fflush(logfile);
  fseek(infile, read_offset, SEEK_SET);
  cloud_put_object("bucket", name , segment_len, put_buffer);
}
        
/*
 * cloudfs_load_infileDS
 * the initial file to segment mappings are first stored in a in-memory
 * structure like a linked list this is written to a file in this function
 * to make it persistent
 */
void cloudfs_load_infileDS(file_mapping **head, file_mapping **tail, char *sbuf)
{
  file_mapping *current;
  current = *head;
  int count = 1;
  while(current!=NULL)
  {
    if(count == 1)
    {
      sprintf(sbuf, "%s %d ", current->hash, current->segment_len);
      count++;
    }
    else
      sprintf(sbuf,"%s%s %d ",sbuf, current->hash, current->segment_len);
    current = current->next;
  }
}

/*
 * cloudfs_update_linked_list_map
 * update the linked list map on addition of a new segment
 */
void cloudfs_update_linked_list_map( int segment_len, char *name, file_mapping **head, file_mapping **tail, int *size)
{
  fprintf(logfile,"Update linkedlist map\n");
  fflush(logfile);
  *size = *size + ((MD5_DIGEST_LENGTH*2)) + 8 +2;
  file_mapping *temp = (file_mapping *)malloc(sizeof(file_mapping));
  temp->segment_len = segment_len;

  memcpy(temp->hash, name, ((MD5_DIGEST_LENGTH * 2)+1));

  if(*head == NULL)
  { 
    temp->next = NULL;
    *head = temp;
    *tail = temp;
  }
  else
  {
    (*tail)->next = temp;
    *tail = temp;
    (*tail)->next=NULL;
  }
}

/*
 * cloudfs_segmentation:
 * This Function divides does the followinf functions
 * 1)Divides the file:path into segments
 * 2)Finds the MD5 hash of these segments
 * 3)Puts these segments into cloud(Only if there are no duplicates)
 * 4)Updates the global lookup table
 * 5)Updates the metafile for the file put in the cloud
 * 6)Metafile is populated by writing metadata into linkedlist and subsequently
 * 7)Writing the linked list data into metafile for persistent storage
 */
void cloudfs_segmentation(char *fpath, int argument)
{
  char cache_path[PATH_MAX];
  if(implement_cache == 1 && exceeded_cache_size == 0)
  {
    char *cpath = (char *)malloc(PATH_MAX);
    convert_name(fpath, cpath);
    char cache[]=".cache/";
    strcpy(cache_path, state_.ssd_path);
    strcat(cache_path, cache);
    strcat(cache_path, cpath);
    free(cpath);
  }
  else
  {
    strcpy(cache_path, fpath);
  }
  fprintf(logfile, "The filename for segmentation is %s\n", cache_path);
  fflush(logfile);
  
  struct stat stat_buf;
  lstat(cache_path, &stat_buf);
  
  fprintf(logfile, "The filesize for segmentation is %lu\n", stat_buf.st_size);
  fflush(logfile);

  FILE *fp;
  int found=0;
  int size = 0;
  file_mapping *head = NULL;
  file_mapping *tail = NULL;
  int metafile_length;

  fp = fopen(cache_path, "rb");
  if(fp == NULL)
    perror("Error open file\n");

  /*uses rabin fingerprinting to find segment boundaries*/
  rabinpoly_t *rp = rabin_init( window_size, avg_seg_size,
                  min_seg_size, max_seg_size);

  if(!rp) {
    fprintf(stderr , "Failed to init rabinhash algorithm\n");
    exit(1);
  }

  MD5_CTX ctx;
  unsigned char md5[MD5_DIGEST_LENGTH];

  char name[(MD5_DIGEST_LENGTH * 2) + 1];
  char buf[1024];
  int bytes;
  int read_offset = 0;
  int len, segment_len = 0, b;
  int new_segment = 0;

  MD5_Init(&ctx);
  /*Reads the file contents iteratively*/
  while((bytes = fread(buf, 1, sizeof(buf), fp)) > 0)
  {
    char *buftoread = (char *)&buf[0];
	/*Performs rabin fingerprinting on these segments*/
    while ((len = rabin_segment_next(rp, buftoread, bytes, &new_segment))>0)
    {
	  /* Finds the md5 hash of each segment which is used to basically identify the
	   * segment later from the cloud
	   */
      MD5_Update(&ctx, buftoread, len);
      segment_len += len;

      if (new_segment)
      {
        MD5_Final(md5, &ctx);
        printf("%u", segment_len);
        fflush(stdout);

				for(b = 0; b < MD5_DIGEST_LENGTH; b++)
        {
					printf("%02x", md5[b]);
          fflush(stdout);
        }
				printf("\n");
  
        for(b = 0; b < MD5_DIGEST_LENGTH; b++)      
          sprintf(&name[b*2], "%02x", md5[b]);
        
        fprintf(logfile, "The segment name: %s and segment_len: %d\n", name, segment_len);
        fflush(logfile);
        
        cloudfs_update_linked_list_map( segment_len, &name[0], &head, &tail, &size);

        found = cloudfs_search_lookup(&md5[0], &name[0], segment_len);
       
		/*Add it to the cloud only if it is not already present*/
        if(found == 0)
        {
          infile = fopen(cache_path, "rb");
          cloudfs_populate_put_segment(infile, segment_len, read_offset, &name[0]);
          fclose(infile);
        }
        else
          printf("Duplication found so not putting in cloud\n");
        
        read_offset = read_offset + segment_len;
				MD5_Init(&ctx);
				segment_len = 0;
			}

			buftoread += len;
			bytes -= len;

			if (!bytes) {
				break;
			}
		}
		if (len == -1) {
			fprintf(stderr, "Failed to process the segment\n");
			exit(2);
		}
	}
	MD5_Final(md5, &ctx);

  for(b = 0; b < MD5_DIGEST_LENGTH; b++) {
		printf("%02x", md5[b]);
	}
  
  for(b = 0; b < MD5_DIGEST_LENGTH; b++)      
    sprintf(&name[b*2], "%02x", md5[b]);
        
  /*updates the linked_list used to store mapping between file and segments*/
  cloudfs_update_linked_list_map( segment_len, &name[0], &head, &tail, &size);

  found=cloudfs_search_lookup(&md5[0], &name[0], segment_len);

  if(found == 0)
  {
    infile = fopen(cache_path, "rb");
    cloudfs_populate_put_segment(infile, segment_len, read_offset, &name[0]);
    fclose(infile);
  }
  else
    printf("Duplication found so not putting in cloud\n");

  if(argument == 1)
    cloudfs_cow_delete(g_metafile_length, fpath, g_size, head);  

  /*Populates the per-file metafile which is persistent from linked list*/
  cloudfs_populate_metafile(size, fpath, &metafile_length,&head, &tail);
  /* Once you have populated the per-file metafile
   * delete the linked list
   */
  cloudfs_clear_linked_list(head); 
  
  lsetxattr(fpath, "user.METASIZE_CLOUD", &metafile_length, sizeof(int), 0 );
  rabin_free(&rp);
  fclose(fp);
}

/*
 * cloudfs_search_lookup
 * It searches the lookup table for a given segment
 * Returns 0 if not found
 * Returns 1 if found
 * Used to avoid putting duplicates into the cloud
 */
int cloudfs_search_lookup(char *md5, char *name, int segment_len)
{
  fprintf(logfile, "Search_lookup\n");
  fflush(logfile);
  unsigned int num = 0;
  int found = 0;
  char *fourth_pos = &num;
  *fourth_pos = md5[0];
  const char empty[] = "empty"; 

  if(strcmp(hashtable[num].hash, empty)==0)
  {
    strcpy(hashtable[num].hash, name);
    hashtable[num].segment_len = segment_len;
    hashtable[num].reference_count = 1; 
  }
  else
  {
    if(hashtable[num].next == NULL)
    {
      if(strcmp(hashtable[num].hash, name)==0)
      {
        hashtable[num].reference_count = hashtable[num].reference_count + 1;
        if(hashtable[num].reference_count == 1)
          return 0;
        found = 1;
        return found;
      }
      lookup *current = (lookup *)malloc(sizeof(lookup));
      hashtable[num].next = current;
      current->reference_count = 1;
      current->segment_len = segment_len;
      strcpy(current->hash, name);
      current->next=NULL;
    }
    else
    {
      if(strcmp(hashtable[num].hash, name)==0)
      {
        hashtable[num].reference_count = hashtable[num].reference_count + 1;
        if(hashtable[num].reference_count == 1)
          return 0;
        found = 1;
        return found;
      }
      
      lookup *current = hashtable[num].next;
      lookup *previous;
      while(current!=NULL)
      {
        if(strcmp(current->hash, name)==0)
        {
          current->reference_count = current->reference_count + 1;
          if(current->reference_count == 1)
            return 0;
          found = 1;
          return found;
        }
        previous = current;
        current = current->next;
      }
      lookup *new_node = (lookup *)malloc(sizeof(lookup));
      previous->next = new_node;
      new_node->reference_count = 1;
      new_node->segment_len = segment_len;
      strcpy(new_node->hash, name);
      new_node->next = NULL;
    }
  }
  return found;
}

/* 
 * cloudfs_clear_linked_list
 * ocne the file to segment mapping is copied to the persistent
 * per-file metafile the linked list is cleared and memory is
 * deallocated
 */ 
void cloudfs_clear_linked_list(file_mapping *head)
{
  fprintf(logfile, "Clear Linked List\n");
  fflush(logfile);
  file_mapping *current = head;
  file_mapping *previous;

  while(current !=NULL)
  {
    previous = current;
    current = current->next;
    free(previous);
  }
}  

/*
 * cloudfs_unlink_metafile
 * Once a given file is delered there is no need to store its
 * segments to file mapping in the metafile so we delete the
 * metafile
 */
int cloudfs_unlink_metafile(char *fpath)
{
  fprintf(logfile, "Unlink Metafile\n");
  fflush(logfile);
  printf("unlink\n");

  char metapath[PATH_MAX]="";
  int retstat = 0;
  cloudfs_convert_filename(fpath, metapath);
  retstat = unlink(metapath);

  if(retstat < 0)
    retstat = cloudfs_error("unlink error");

  int metafile_length = 0;

  lsetxattr(fpath, "user.METASIZE_CLOUD", &metafile_length, sizeof(int), 0 );
  return retstat;
}

/*
 * cloudfs_read_metafile
 * This is used to read the metafile which stored the file to segment mapping
 * it stores in the same order used to build back the file from segments
 * if populate_file = 1 => function is used to build back the file from the segments
 * if populate_file = 0 => function is used to delete all the segments of a particular
 * file from the cloud
 */
void cloudfs_read_metafile(int metafile_length, char *fepath, off_t filesize, int populate_file)
{
  fprintf(logfile, "read metafile\n");
  fflush(logfile);
  printf("read metafile");
  char *sbuf = (char *)malloc(metafile_length+1); 
  FILE *metastruct;
  char metapath[PATH_MAX]="";
  cloudfs_convert_filename(fepath, metapath);
  metastruct = fopen(metapath, "r");

  fread(sbuf,1 , metafile_length, metastruct);
  sbuf[metafile_length]='\0';

  fclose(metastruct);
  
  if(populate_file == 1)
  {
    printf("Here for retrieving data\n");
    cloudfs_retrieving_data(fepath, sbuf, filesize);
  }

  if(populate_file == 0)
  {
    printf("Here for deleting records\n");
    cloudfs_delete_records(sbuf);
  }
  free(sbuf);
}

void cloudfs_cow_delete(int metafile_length, char *fpath, off_t filesize, file_mapping *head)
{
  fprintf(logfile, "cloudfs cow delete\n");
  fflush(logfile);
  char *sbuf = (char *)malloc(metafile_length+1); 
  FILE *metastruct;
  char metapath[PATH_MAX]="";

  cloudfs_convert_filename(fpath, metapath);
  metastruct = fopen(metapath, "r");

  fread(sbuf,1 , metafile_length, metastruct);
  sbuf[metafile_length]='\0';
  fclose(metastruct);

  cow *temp, *current;
  cow *previous = NULL;
  file_mapping *current_map = head;
 
  int segment_len,ret;
  char hash[(MD5_DIGEST_LENGTH*2)+1];
  char buf[(MD5_DIGEST_LENGTH*2)+ 6 + 3];

  while((sscanf(sbuf, "%s %d ", hash, &segment_len)) == 2)
  {
    if(cow_head == NULL)
    {
      temp = (cow *)malloc(sizeof(cow));
      temp->segment_len = segment_len;
      strcpy(temp->hash, hash);
      temp->found = 0;
      temp->next = NULL;
      cow_head = temp;
      previous = temp;
    }
    else
    {
      temp = (cow *)malloc(sizeof(cow));
      temp->segment_len = segment_len;
      strcpy(temp->hash, hash);
      temp->found = 0;
      temp->next = NULL;
      previous->next = temp;
      previous = temp;
    }
    ret = sprintf(buf,"%s %d ", hash, segment_len);
    sbuf=sbuf+ret;
  }

  free(sbuf);
  
  current = cow_head;
  while(current != NULL)
  {
    current_map = head;
    while(current_map != NULL)
    {
      if(strcmp(current_map->hash, current->hash)==0)
      {
        current->found = 1;
        break;
      }
    current_map = current_map->next;
    }
    current = current->next;
  }
  cow_delete();
  cow_head = NULL;
}

void cow_delete()
{
  cow *current = cow_head;
  while(current != NULL)
  {
    if(current->found == 0)
      cloudfs_reduce_count(current->hash);
    current = current->next;
    free(current);
  }
}


void cloudfs_delete_records(char *sbuf)
{
  fprintf(logfile, "Cloudfs delete records\n");
  fflush(logfile);
  printf("Delete records\n");
  int segment_len,ret;
  char hash[(MD5_DIGEST_LENGTH*2)+1];
  
  char buf[(MD5_DIGEST_LENGTH*2)+ 6 + 3];

  while((sscanf(sbuf, "%s %d ", hash, &segment_len)) == 2)
  {
    ret = sprintf(buf,"%s %d ", hash, segment_len);
    cloudfs_reduce_count(&hash[0]);
    sbuf=sbuf+ret;
  }
}
 
/*
 * cloudfs_reduce_count
 * once a given file is deleted all its segments reference counts
 * are reduced by 1 in the lookup table, they are not deleted straightaway 
 * because the same segment might be a part of another file, hence to 
 * preserve integerity of other files we delete only if reference 
 * count = 0 after decerementing, i.e. no other files refer to this segment
 */
void cloudfs_reduce_count(char *hash)
{
  fprintf(logfile, "Cloud reduce count\n");
  fflush(logfile);
  printf("cloudfs_reduce_count\n");
  unsigned int num;
  char myhash[(MD5_DIGEST_LENGTH*2)+1];
  strcpy(myhash, hash);
  myhash[2]='\0';
  int found = 0;

  num = strtol(myhash, NULL, 16);
 
  /*iteratively search for this segment*/
  if(strcmp(hashtable[num].hash, hash) != 0)
  {
      lookup *current;
      current = hashtable[num].next;
      while(current != NULL)
      {
        if(strcmp(current->hash, hash)!=0)
          current = current->next;
        else if(strcmp(current->hash, hash)==0)
        {
          current->reference_count = current->reference_count - 1;
         
		  /*Delete segment if reference count = 0*/
          if(current->reference_count == 0)
            cloud_delete_object("bucket", current->hash);
          found = 1;
          return;
        }
      }      
  }
  else if(strcmp(hashtable[num].hash, hash) == 0)
  {
    fprintf(logfile, "The reference count before for %s is %d\n", hashtable[num].hash, hashtable[num].reference_count);
    hashtable[num].reference_count = hashtable[num].reference_count - 1;
    fprintf(logfile, "The reference count after for %s is %d\n", hashtable[num].hash, hashtable[num].reference_count);

    if(hashtable[num].reference_count == 0)
     cloud_delete_object("bucket", hashtable[num].hash);
    found = 1;
    return;
  }

  if(found == 0)
      printf("Entry not found where it was expected\n");

}
 
/*
 * cloudfs_populate_metafile
 * This function populates the metafile which stores the file to segment mapping
 * from the in memory linked list. This is done to make this mapping data persistent
 */
void cloudfs_populate_metafile(int size, char *fpath, int *metafile_length, file_mapping **head, file_mapping **tail)
{
  char *sbuf = (char *)malloc(size+1);
  FILE *metastruct;
  char metapath[PATH_MAX]="";

  cloudfs_convert_filename(fpath, metapath);

  /*Open with "w" so that it just writes and gets truncated on fresh open*/
  metastruct = fopen(metapath, "w");

  cloudfs_load_infileDS(head, tail, sbuf);
  
  fprintf(metastruct, "%s", sbuf);

  *metafile_length = strlen(sbuf);
  fclose(metastruct);
  free(sbuf);
}

/*
 * cloudfs_retrieving_data
 * This function runs through the per-file metafile and populates back the
 * file from the segment to file mapping
 */
void cloudfs_retrieving_data(char *fpath, char *sbuf, off_t file_size)
{
  int segment_len,ret;
  char hash[(MD5_DIGEST_LENGTH*2)+1];
  
  char buf[(MD5_DIGEST_LENGTH*2)+ 6 + 3];

  outfile = fopen(fpath, "wb");
  while((sscanf(sbuf, "%s %d ", hash, &segment_len)) == 2)
  {
    cloud_get_object("bucket", hash, get_buffer);
    ret = sprintf(buf,"%s %d ", hash, segment_len);
    cloud_print_error();
    sbuf=sbuf+ret;
  }
  fclose(outfile);

}

/*
 * cloudfs_convert_filename
 * THe per-file metafile is named by appending a '.' to the actual filename to make
 * it hidden, this function converts to the hidden format when given the actual name
 */
void cloudfs_convert_filename(char *fpath, char *metapath)
{
  char *current_path = fpath;
  char *previous = current_path;

  while(strstr(current_path, "/")!=NULL)
    current_path++;
  
  char *unchanged = (char *)malloc((current_path - previous)+1);
  strncpy(unchanged, previous, ((current_path - previous)));
 
  unchanged[current_path-previous]='\0';
  strcpy(metapath , unchanged); 
  strcat(metapath, ".");
  strcat(metapath, current_path);
  
  free(unchanged);
}

/*
 * cache_release
 * This function is called only if cache is implemented
 * This is used to release the file back into cloud, ssd or cache
 * accordinly after the read or write operation has been performed
 */
int cache_release(const char *path, struct fuse_file_info *fi)
{
  fprintf(logfile, "Cache release\n");
  fflush(logfile);
  int retstat = 0;
  int in_cloud = 0;
  int filesize = 0;
  int metasize = 0;

  char fpath[PATH_MAX];
  strcpy(fpath, state_.ssd_path);
  strcat(fpath, path);

  struct stat stat_buf;
  lstat(fpath, &stat_buf);

  lgetxattr(fpath,"user.IN_CLOUD", &in_cloud, sizeof(int));
  lgetxattr(fpath,"user.METASIZE_CLOUD", &metasize, sizeof(int));
  lsetxattr(fpath,"user.SIZE_CLOUD", &stat_buf.st_size, sizeof(off_t), 0);

  /* If size less than threshold to put in cache or cloud
   * Keep it in its normal location
   */
  if(stat_buf.st_size <= state_.threshold)
  {
    printf("Size less than state_.threshold\n");
    fflush(stdout);
	/*If it pre-existed in cloud delete it from cloud*/
    if(g_in_cloud == 1)
    {
	  /*if segmentation is used delete by reading from metafile*/
      if(segmentation == 0)
      {
        if(g_metafile_length !=0 )
          cloudfs_read_metafile(g_metafile_length, fpath, g_size, 0);

        printf("Listing Object in < state_.threshold category after deletion\n");
        cloud_list_bucket("bucket", list_bucket);
        in_cloud = 0;
        lsetxattr(fpath,"user.IN_CLOUD", &in_cloud, sizeof(int), 0);
        cloudfs_unlink_metafile(fpath);
      } 
	  /*If segementation is not used just delete the while file from cloud*/
      if(segmentation == 1)
      {
        printf("Deleting modified object \n");
        char *cpath = (char *)malloc(PATH_MAX);
        convert_name(fpath, cpath);
        cloud_delete_object("bucket",cpath);
        printf("Listing Object \n");
        cloud_list_bucket("bucket", list_bucket);
        free(cpath);
        in_cloud = 0;
        lsetxattr(fpath,"user.IN_CLOUD", &in_cloud, sizeof(int), 0);
      }
    }

	/*If it pre-existed in cache delete it from cache*/
    if(g_in_ssd == 1)
    {
      cache_delete(fpath);
      cache_delete_list(fpath);
    }
  }

  /*If size > threshold to put in cache/cloud*/
  if(stat_buf.st_size > state_.threshold)
  {

    off_t remaining_cache_size;
    lgetxattr(fpath,"user.SIZE_CLOUD", &filesize, sizeof(off_t));

	/*If it pre-existed in cache, delete it from cache*/
    if(g_in_ssd == 1)
    {
      cache_delete(fpath);
      cache_delete_list(fpath);
    }

	/* If file size bigger than cache size evict it to cloud
	 * even though its most recently used as it cannot be stored
	 * in cache
	 */
    if(stat_buf.st_size > total_cache_size)
    {
      fprintf(logfile, "File size greater thatn total_cache\n");
      fflush(logfile);
      if(in_dirty == 0 && segmentation == 0 && g_in_cloud == 1)
      else
      {
        exceeded_cache_size = 1;
        cache_evict_cloud(fpath);
      }
    }

    else
    {
      remaining_cache_size = total_cache_size - current_cache_size;
	  /* If the size left in cache is lesser than file size evict file
	   * to cloud even though it is most recently used
	   */
      if(remaining_cache_size < stat_buf.st_size)
      {
        cache_eviction(stat_buf.st_size - remaining_cache_size);
      }
      fprintf(logfile, "Adding %s to cache\n", fpath);
      cache_add(fpath);
      cache_addbuild_list(max_lru, fpath, stat_buf.st_size);

	  /* Delete the file from cloud if it pre-existed there
	   * as it is the most recently used and hence is going
	   * to be stored in cache
	   */
      if(g_in_cloud == 1)
     {
        if(segmentation == 0)
        {
          if(metasize !=0)
            cloudfs_read_metafile(metasize, fpath, filesize, 0);
          
          printf("Listing Object in > state_.threshold category after deletion\n");
          cloud_list_bucket("bucket", list_bucket);

          in_cloud = 0;
          lsetxattr(fpath,"user.IN_CLOUD", &in_cloud, sizeof(int), 0);
          cloudfs_unlink_metafile(fpath);
        }

        if(segmentation == 1)
        {
          char *cpath = (char *)malloc(PATH_MAX);
          convert_name(fpath, cpath);
          cloud_delete_object("bucket",cpath);
          printf("Listing Object \n");
          cloud_list_bucket("bucket", list_bucket);
          free(cpath);
          in_cloud = 0;
          lsetxattr(fpath,"user.IN_CLOUD", &in_cloud, sizeof(int), 0);
        }
      }
    }
	/* Truncate file in it on-disk location as it is now stored in cache */
    cloudfs_truncate(path, 0);
  }
 
  in_dirty = 0;
  g_in_ssd = 0;
  g_in_cloud = 0;
  g_size = 0;
  g_metafile_length = 0;
  exceeded_cache_size = 0;
 
  retstat = close(fi->fh);
  exceeded_cache_size =0;
  return retstat;
}

/*
 * cache_eviction
 * when cache is full and there is no place to add a 
 * new entry this function deleted files from the cache 
 * and puts them on the cloud
 */
int cache_eviction(off_t required_size)
{
  int retstat = 0;
  off_t deleted_size = 0;
  cache_list *current;
  current = cache_tail;
  char fpath[PATH_MAX];
 
  while(deleted_size < required_size && current!= NULL)
  {
    strcpy(fpath, current->name);
    cache_evict_cloud(fpath);
    cache_delete(fpath);
    deleted_size = deleted_size + current->size;
    current = current->prev;
    cache_delete_list(fpath);
  }
  fprintf(logfile, "Reached Out of Eviction Loop\n");
  fflush(logfile);
  return retstat;
}

/*
 * cache_evict_cloud
 * Used to put object from cache => cloud
 */
int cache_evict_cloud(char *fpath)
{
  int retstat = 0;
  int in_cloud = 0;
  if(segmentation == 0)
  {
    if(exceeded_cache_size == 1)
      cloudfs_segmentation(fpath, 1);
    else
      cloudfs_segmentation(fpath, 0);

    printf("Listing Object after addition\n");
    cloud_list_bucket("bucket", list_bucket);
    in_cloud = 1;
    lsetxattr(fpath,"user.IN_CLOUD", &in_cloud, sizeof(int), 0);
  }

  if(segmentation == 1)
  {
      char *cpath = (char *)malloc(PATH_MAX);
      convert_name(fpath, cpath);
  
      char cache_path[PATH_MAX];
      char cache[]=".cache/";
      strcpy(cache_path, state_.ssd_path);
      strcat(cache_path, cache);
      strcat(cache_path, cpath);
      
      struct stat stat_buf;
      lstat(cache_path, &stat_buf);


      infile = fopen(cache_path, "rb"); 
      cloud_put_object("bucket", cpath, stat_buf.st_size, put_buffer);
      cloud_list_bucket("bucket", list_bucket);
      fclose(infile);
      free(cpath);

      cloud_list_bucket("bucket", list_bucket);
      in_cloud = 1;
      lsetxattr(fpath,"user.IN_CLOUD", &in_cloud, sizeof(int), 0);
  }
  return retstat;
}

/*
 * cache_add
 * Adds an object to the cache
 */
int cache_add(char *fpath)
{
  fprintf(logfile, "Cache add\n");
  fflush(logfile);
  printf("Cache add\n");
  fflush(stdout);
  int retstat = 0;
  int in_ssd = 0;
  FILE *cp, *fp;
  
  char cpath[PATH_MAX];
  convert_name(fpath, cpath);

  char cache_path[PATH_MAX];
  char cache[]=".cache/";
  strcpy(cache_path, state_.ssd_path);
  strcat(cache_path, cache);
  strcat(cache_path, cpath);

  cp = fopen(cache_path, "wb+");
  fp = fopen(fpath, "rb+");
  
  struct stat stat_buf;
  lstat(fpath, &stat_buf);


  char buf[1024];
  size_t return_size;

  while((return_size = fread(buf, 1, 1024, fp))>0)
    fwrite(buf, 1, return_size, cp);

  fclose(cp);
  fclose(fp);

  /*The in_ssd attribute set to keep in track of the file*/
  in_ssd = 1;
  lsetxattr(fpath,"user.IN_SSD", &in_ssd, sizeof(int), 0);
  return retstat;
}

/*
 * cache_add_list
 * The new entry is added to the linked list which helps us to keep in track of all elements in the cache
 * Its added at the front so that LRU is evicted as eviction happens from back
 */
int cache_add_list(char *fpath)
{
  int retstat = 0;
  off_t filesize;

  lgetxattr(fpath,"user.SIZE_CLOUD", &filesize, sizeof(off_t));

  fprintf(logfile, "The name %s and size %jd was added to list\n", fpath, filesize);

  cache_list *temp = (cache_list *)malloc(sizeof(cache_list));
  strcpy(temp->name, fpath);
  temp->size = filesize;
  temp->cost = max_lru;
  temp->prev = NULL;
  temp->next = cache_head;
  if(cache_head == NULL)
    cache_tail = temp;
  else
    temp->next->prev = temp;
  cache_head = temp;

  return retstat;
}

/*
 * cache_delete
 * This deletes an object from the cache
 */ 
int cache_delete(char *fpath)
{
  int retstat = 0;
  int in_ssd = 0; 
  char cpath[PATH_MAX];
  convert_name(fpath, cpath);
  
  char cache_path[PATH_MAX];
  char cache[]=".cache/";
  strcpy(cache_path, state_.ssd_path);
  strcat(cache_path, cache);
  strcat(cache_path, cpath);
  
  struct stat stat_buf;
  lstat(cache_path, &stat_buf);

  current_cache_size = current_cache_size - stat_buf.st_size;
  
  retstat = unlink(cache_path);
  if(retstat < 0)
    retstat = cloudfs_error("unlink error");
  
  in_ssd = 0;
  lsetxattr(fpath,"user.IN_SSD", &in_ssd, sizeof(int), 0);
  return retstat;
}

/*
 * cache_delete_list
 * This deletes an object from the linked list that keeps
 * track of cache elements
 */ 
int cache_delete_list(char *fpath)
{
  int retstat = 0;

  cache_list *current = cache_head;
  while(current != NULL)
  {
    if(strcmp(current->name, fpath)==0)
    {
      if(current == cache_head)
      {
        if(current->next == NULL)
        {
          cache_head = NULL;
          cache_tail = NULL;
          free(current);
          return retstat;
        }
        if(current->next != NULL)
        {
          cache_head = current->next;
          cache_head->prev = NULL;
          free(current);
          return retstat;
        }
      }

      else if(current == cache_tail)
      {
        current->prev->next = NULL;
        cache_tail= current->prev;
        free(current);
        return retstat;
      }
        
      current->prev->next = current->next;
      current->next->prev = current->prev;
      free(current);
      return retstat;
    }
    current = current->next;
  }
  return retstat;
}

/*
 * cloudfs_release
 * This releases an object into the cloud, cache or keeps in the 
 * original location accordingly after the file is used
 */ 
int cloudfs_release(const char *path, struct fuse_file_info *fi)
{
  int retstat = 0;
  if(implement_cache == 1)
  {
    cache_release(path, fi);
    return retstat;
  }

  int in_cloud = 0;
  char fpath[PATH_MAX];
  strcpy(fpath, state_.ssd_path);
  strcat(fpath, path);

  struct stat stat_buf;
  lstat(fpath, &stat_buf);

  lgetxattr(fpath,"user.IN_CLOUD", &in_cloud, sizeof(int));
  lsetxattr(fpath,"user.SIZE_CLOUD", &stat_buf.st_size, sizeof(off_t), 0);
 
  /*If segmentation is used and the size is > threshold*/
  if(stat_buf.st_size > state_.threshold && segmentation == 0)
  {
	/*If a write operation has been performed and file is modified*/  
    if(in_dirty==1)
    {
	  /*If it was already in cloud dont put the unchanged segments*/
      if(g_metafile_length != 0 && g_in_cloud == 1)
        cloudfs_segmentation(fpath, 1);
      else
        cloudfs_segmentation(fpath, 0);
    }
	/* Truncate the file from its original location so it does not
	 * occupy space
	 */
    cloudfs_truncate(path, 0);
    in_cloud = 1;
    lsetxattr(fpath,"user.IN_CLOUD", &in_cloud, sizeof(int), 0);
  }
 
  /*If size > threshold but segmentation is not used*/
  if(stat_buf.st_size > state_.threshold && segmentation == 1)
  {
	/*If there was a write operation*/  
    if(in_dirty==1)
    {
      char *cpath = (char *)malloc(PATH_MAX);
      convert_name(fpath, cpath);

      infile = fopen(fpath, "rb"); 
      printf("Putting Object \n");
	  /*Put the entite file in cloud*/
      cloud_put_object("bucket", cpath, stat_buf.st_size, put_buffer);
      fclose(infile);
      free(cpath);

      printf("Listing Object \n");
      cloud_list_bucket("bucket", list_bucket);
    }
    in_cloud = 1;
    lsetxattr(fpath,"user.IN_CLOUD", &in_cloud, sizeof(int), 0);
    cloudfs_truncate(path, 0);
  }
  
  /*If size >= threshold and file was previously in cloud and segmentation is not used*/
  if(stat_buf.st_size <= state_.threshold && in_cloud == 1 && segmentation == 1)
  {
    printf("Deleting modified object \n");
    char *cpath = (char *)malloc(PATH_MAX);
    convert_name(fpath, cpath);
    cloud_delete_object("bucket",cpath);
    free(cpath);
    in_cloud = 0;
    lsetxattr(fpath,"user.IN_CLOUD", &in_cloud, sizeof(int), 0);
  }
  
  /*If size >= threshold and file was previously in cloud and segmentation is used*/
  if(stat_buf.st_size <= state_.threshold && in_cloud == 1 && segmentation == 0)
  {
    if(g_metafile_length !=0 )
      cloudfs_read_metafile(g_metafile_length, fpath, g_size, 0);
    
    in_cloud = 0;
    lsetxattr(fpath,"user.IN_CLOUD", &in_cloud, sizeof(int), 0);
    cloudfs_unlink_metafile(fpath);
  }
  
  in_dirty = 0;
  g_size = 0;
  g_in_cloud = 0;
  g_metafile_length = 0;
  retstat = close(fi->fh);
  printf("release\n");
  return retstat;
}

int cloudfs_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
  int retstat = 0;
  if(datasync)
    retstat = fdatasync(fi->fh);
  else
    retstat = fsync(fi->fh);

  if(retstat < 0)
    cloudfs_error("sync error");
  printf("fsync\n");
  return retstat;
}

int cloudfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
  int retstat = 0;
  char fpath[PATH_MAX];
  strcpy(fpath, state_.ssd_path);
  strcat(fpath, path);

  retstat = lsetxattr(fpath, name, value, size, flags);
  if(retstat < 0)
    retstat = cloudfs_error("setxattr error");
  printf("set x attr\n");
  return retstat;
}

int cloudfs_getxattr(const char *path, const char *name, char *value, size_t size)
{
  int retstat = 0;
  char fpath[PATH_MAX];
  printf("[%s]The state is %s\n",__func__, state_.ssd_path);
  strcpy(fpath, state_.ssd_path);
  strcat(fpath, path);
  printf("The path in getxattr is %s\n", path);

  retstat = lgetxattr(fpath, name, value, size);
  if(retstat < 0)
    retstat = cloudfs_error("cloudfs_getxattr error");
  printf("get x attr\n");
  return retstat;
}

int cloudfs_listxattr(const char *path, char *list, size_t size)
{
  int retstat = 0;
  char fpath[PATH_MAX];
  strcpy(fpath, state_.ssd_path);
  char *ptr;

  strcat(fpath, path);
  retstat = llistxattr(fpath, list, size);
  if(retstat < 0)
    retstat = cloudfs_error("error listxattr");
  for(ptr = list; ptr < list+retstat; ptr += strlen(ptr)+1)
    printf("  \"%s\"\n", ptr);
  printf("List x attr\n");
  return retstat;
}

int cloudfs_removexattr(const char *path, const char *name)
{
  printf("Remove x attr\n");
  return 0;
}

int cloudfs_opendir(const char *path, struct fuse_file_info *fi)
{
  DIR *dp;
  int retstat = 0;
  char fpath[PATH_MAX];
  strcpy(fpath, state_.ssd_path);
  strcat(fpath, path);

  dp = opendir(fpath);
  if(dp == NULL)
    retstat = cloudfs_error("open dir error"); 
  fi->fh = (intptr_t) dp;
  printf("Open directory\n");
  return retstat;
}

int cloudfs_releasedir(const char *path, struct fuse_file_info *fi)
{
  int retstat = 0;
  closedir((DIR *) (uintptr_t) fi->fh);
  printf("Release directory\n");
  return retstat;
}

int cloudfs_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi)
{
  int retstat = 0;
  printf("fsyncdir\n");
  return retstat;
}

int cloudfs_access(const char *path, int mask)
{
  int retstat = 0;
  char fpath[PATH_MAX];
  strcpy(fpath, state_.ssd_path);
  strcat(fpath, path);

  retstat = access(fpath, mask);
  if (retstat < 0)
    retstat = cloudfs_error("cloud_access");
  printf("access\n");
  return retstat;
}

int cloudfs_ftruncate(const char *path, off_t offset, struct fuse_file_info *fi)
{
  int retstat = 0;
  retstat = ftruncate(fi->fh, offset);
  if(retstat < 0)
    retstat = cloudfs_error("ftruncate error");
  printf("ftruncate\n");
  return retstat;
}

int cloudfs_fgetattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi)
{
  int retstat = 0;
  int in_cloud = 0;
  char fpath[PATH_MAX];
  strcpy(fpath, state_.ssd_path);
  strcat(fpath, path);

  retstat = fstat(fi->fh, statbuf);
  if(retstat < 0)
    retstat = cloudfs_error("error fgetattr");
  printf("fgetattr\n");
  lgetxattr(fpath,"user.IN_CLOUD", &in_cloud, sizeof(int));
  if(in_cloud != 0)
  {
    lgetxattr(fpath,"user.SIZE_CLOUD", &statbuf->st_size, sizeof(off_t));
  }
  return retstat;
}

/*
 * Functions supported by cloudfs 
 */
static 
struct fuse_operations cloudfs_operations = {
  .init = cloudfs_init,
  .getattr = cloudfs_getattr,
  .mkdir = cloudfs_mkdir,
  .readdir = cloudfs_readdir,
  .destroy = cloudfs_destroy,
  .readlink = cloudfs_readlink,
  .getdir = NULL,
  .mknod = cloudfs_mknod,
  .unlink = cloudfs_unlink,
  .rmdir = cloudfs_rmdir,
  .symlink = cloudfs_symlink,
  .rename = cloudfs_rename,
  .link = cloudfs_link,
  .chmod = cloudfs_chmod,
  .chown = cloudfs_chown,
  .truncate = cloudfs_truncate,
  .utime = cloudfs_utime,
  .open = cloudfs_open,
  .read = cloudfs_read,
  .write = cloudfs_write,
  .statfs = cloudfs_statfs,
  .flush = cloudfs_flush,
  .release = cloudfs_release,
  .fsync = cloudfs_fsync,
  .setxattr = cloudfs_setxattr,
  .getxattr = cloudfs_getxattr,
  .listxattr = cloudfs_listxattr,
  .removexattr = cloudfs_removexattr,
  .opendir = cloudfs_opendir,
  .releasedir = cloudfs_releasedir,
  .fsyncdir = cloudfs_fsyncdir,
  .access = cloudfs_access,
//  .create = cloudfs_create,
  .ftruncate = cloudfs_ftruncate,
 .fgetattr = cloudfs_fgetattr
};

int cloudfs_start(struct cloudfs_state *state,
                  const char* fuse_runtime_name) {

  int argc = 0;
  char* argv[10];
  argv[argc] = (char *) malloc(128 * sizeof(char));
  strcpy(argv[argc++], fuse_runtime_name);
  argv[argc] = (char *) malloc(1024 * sizeof(char));
  strcpy(argv[argc++], state->fuse_path);
  
  argv[argc++] = "-s"; // set the fuse mode to single thread
//  argv[argc++] = "-f"; // run fuse in foreground 
  
  state_  = *state;
  logfile = fopen("/tmp/temp_log", "a+");
  setvbuf(logfile, NULL, _IOLBF, 0);

  int fuse_stat = fuse_main(argc, argv, &cloudfs_operations, NULL);
  

    
  return fuse_stat;
}
