#include<stdio.h>
#include<stdlib.h>
#include<dirent.h>

#include "SHA_256.h"

typedef struct
{
    char dir_name[100];
    char hash[65];
}leaves;

leaves *merkle_leaves;

int count = 0;

int open_dir(char *path);
void hash_file(char *file);
void hash_data(char *data);
void strToHexa(unsigned char *str, char *strInHex);
void free_branches(char *merkle_branches[], int len);
char* create_ent(char *ptr, char *path, char *name, int len);
int create_merkle_tree();
static int sort_alphabetically(const void *l, const void *r);

int main(int argc, char *argv[]){

    // check input
    if(argc != 2)
    {
        printf("Usage: prg_name folder_name or path");
        return 1;
    }

    // Create Merkle Leaves - open directory and hash its content
    merkle_leaves = calloc(1, sizeof(leaves));
    if (merkle_leaves == NULL)
    {
        fprintf(stderr, "malloc: %s\n", strerror(errno));
        return 1;
    }
    int i = open_dir(argv[1]);
    if (i == 1){
        printf("Faild\n");
        return 1;
    }

    // Create Merkle Branches and produce the Merkle Root
    i = create_merkle_tree();
    if (i == 1){
        printf("Faild\n");
        return 1;
    }

    return 0;
}

int create_merkle_tree()
{
    // Allocate a temporary memory
    char *tmp = malloc(129);
    if (tmp == NULL)
    {
        fprintf(stderr, "malloc: %s\n", strerror(errno));
        free(merkle_leaves);
        return 1;
    }

    // Track how many Merkle leaves remain
    int remain_count = count;

    // Arrey to hold merkle branches
    char *merkle_branches[(count/2)+1];

    // How many merkle_branches have been filled
    int n_count = 0;

    unsigned char *data_Hash = NULL;

    // Create Merkle branches from Merkle leaves- Concatenate hashes and hash them
    while(remain_count > 0){
        // if one Merkle leaf remain concatenate it with itself
        if (remain_count == 1)
        {
            printf("Hash of %s: %s\n", merkle_leaves[count-1].dir_name, merkle_leaves[count-1].hash);

            // concatenate it with ifself
            memcpy(tmp, merkle_leaves[count-1].hash, 64);
            memcpy(&tmp[64], merkle_leaves[count-1].hash, 64);
            tmp[128] = '\0';

            // hash tmp
            data_Hash = sha_256_data(tmp);
            if(data_Hash == NULL){
                printf("String hashing failed\n");
                free(tmp);
                free(merkle_leaves);
                free_branches(merkle_branches, n_count);
                return 1;
            }

            // allcocate memory and convert the hash into hex form
            merkle_branches[n_count] = malloc(65);
            if(merkle_branches[n_count] == NULL)
            {
                fprintf(stderr, "malloc: %s\n", strerror(errno));
                free(tmp);
                free(merkle_leaves);
                free(data_Hash);
                free_branches(merkle_branches, n_count);
                return 1;
            }
            strToHexa(data_Hash, merkle_branches[n_count]);
            free(data_Hash);
            data_Hash = NULL;

            if(count == 1) printf("Merkle Root: %s\n\n", merkle_branches[n_count]);
            else {
                printf("--Branch %i: %s\n", n_count+1, merkle_branches[n_count]);
                n_count++;
                printf("\n");

                printf("-------------------------------------------------------------------------------\n");
            }
            remain_count --;
        }
        else
        {

            printf("Hash of %s: %s\n", merkle_leaves[count-remain_count].dir_name, merkle_leaves[count-remain_count].hash);
            printf("Hash of %s: %s\n", merkle_leaves[count-remain_count+1].dir_name, merkle_leaves[count-remain_count+1].hash);

            // concatenate hashes
            memcpy(tmp, merkle_leaves[count-remain_count].hash, 64);
            memcpy(&tmp[64], merkle_leaves[count-remain_count+1].hash, 64);
            tmp[128] = '\0';

            // hash tmp
            data_Hash = sha_256_data(tmp);
            if(data_Hash == NULL){
                printf("String hashing failed\n");
                free(tmp);
                free(merkle_leaves);
                free_branches(merkle_branches, n_count);
                return 1;
            }

            // allcocate memory and convert the hash into hex form
            merkle_branches[n_count] = malloc(65);
            if(merkle_branches[n_count] == NULL)
            {
                fprintf(stderr, "malloc: %s\n", strerror(errno));
                free(tmp);
                free(merkle_leaves);
                free(data_Hash);
                free_branches(merkle_branches, n_count);
                return 1;
            }
            strToHexa(data_Hash, merkle_branches[n_count]);
            free(data_Hash);
            data_Hash = NULL;
            
            if (count == 2) printf("Merkle Root: %s\n\n", merkle_branches[n_count]);
            else {
                printf("--Branch %i: %s\n", n_count+1, merkle_branches[n_count]);
                n_count++;
                printf("\n");

                if(remain_count == 2)
                    printf("-------------------------------------------------------------------------------\n");
            }
            remain_count -= 2;
        }
    }

    free(merkle_leaves);

    // remember how much memory to free
    int free_count = n_count;

    int c;

    while(n_count > 1)
    {
        // set new count
        count = n_count;
        remain_count = count;
        n_count = 0;

        // concatenate hashes and hash them
        while(remain_count > 0){
            // if a single Merkel branch remain
            if(remain_count == 1){
                printf("Branch%i: %s\n", count, merkle_branches[count-1]);

                memcpy(tmp, merkle_branches[count-1], 64);
                memcpy(&tmp[64], merkle_branches[count-1], 64);
                tmp[128] = '\0';

                data_Hash = sha_256_data(tmp);
                if(data_Hash == NULL){
                    printf("String hashing failed\n");
                    free(tmp);
                    free_branches(merkle_branches, free_count);
                    return 1;
                }

                strToHexa(data_Hash, merkle_branches[n_count]);
                free(data_Hash);
                data_Hash = NULL;

                printf("--Branch %i: %s\n", n_count+1, merkle_branches[n_count]);
                n_count++;
                printf("\n");

                printf("-------------------------------------------------------------------------------\n");
                remain_count--;
            }
            else
            {
                c = count-remain_count;

                printf("Branch%i: %s\n", c+1, merkle_branches[c]);
                printf("Branch%i: %s\n", c+2, merkle_branches[c+1]);

                memcpy(tmp, merkle_branches[c], 64);
                memcpy(&tmp[64], merkle_branches[c+1], 64);
                tmp[128] = '\0';

                data_Hash = sha_256_data(tmp);
                if(data_Hash == NULL){
                    printf("String hashing failed\n");
                    free(tmp);
                    free_branches(merkle_branches, free_count);
                    return 1;
                }

                strToHexa(data_Hash, merkle_branches[n_count]);
                free(data_Hash);
                data_Hash = NULL;

                if(remain_count == 2 && n_count == 0)
                    printf("Merkle Root: %s\n", merkle_branches[n_count]);
                else if(remain_count == 2 && n_count != 0){
                    printf("--Branch %i: %s\n", n_count+1, merkle_branches[n_count]);
                    n_count++;
                    printf("-------------------------------------------------------------------------------\n");
                }
                else{
                    printf("--Branch %i: %s\n", n_count+1, merkle_branches[n_count]);
                    n_count++;
                }

                printf("\n");

                remain_count -= 2;
            }
        }
    }

    free_branches(merkle_branches, free_count);
    free(tmp);
    return 0;
}

void free_branches(char *merkle_branches[], int len)
{
    for(int i = 0; i < len; i++)
        free(merkle_branches[i]);
}

void strToHexa(unsigned char *str, char *strInHex){
    int i = 0, j = 0;
    for (; i < 32; i++, j += 2) {
        sprintf(strInHex + j, "%02x", str[i]);
    }
    strInHex[j] = '\0';
}

int open_dir(char *path)
{
    struct dirent *entry;
    DIR *dp;

    // Open directory
    dp = opendir(path);
    if (dp == NULL)
    {
        perror("opendir");
        return 1;
    }

    int status;
    struct stat st_buf;

    int path_length = strlen(path), len_ent;
    char *ent = malloc(1);
    if(ent == NULL){
        fprintf(stderr, "malloc: %s\n", strerror(errno));
        closedir(dp);
        return 1;
    }

    int index = 0;
    char **file_array = malloc(1 * sizeof(char *));
    if(file_array == NULL){
        fprintf(stderr, "malloc: %s\n", strerror(errno));
        free(ent);
        closedir(dp);
        return 1;
    }
    char **tmp = NULL;

    while((entry = readdir(dp)))
    {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0){
            ent = create_ent(ent, path, entry->d_name, path_length);
            if(ent == NULL){
                free(file_array);
                closedir(dp);
                return 1;
            }

            // Get the status
            status = stat(ent, &st_buf);
            if (status != 0) {
                printf ("Error %d\n", errno);
                free(ent);
                free(file_array);
                closedir(dp);
                return 1;
            }
            if (S_ISDIR(st_buf.st_mode)) // if it is a directory, open it
                open_dir(ent);
            else // if it is a file, add it to file_array
            {
                // add pointer
                tmp = realloc(file_array, (index+1) * sizeof(char *));
                if(tmp == NULL){
                    fprintf(stderr, "realloc: %s\n", strerror(errno));
                    free(ent);
                    if(index > 0)
                        for(int j = 0; j < index; j++)
                            free(file_array[j]);
                    free(file_array);
                    closedir(dp);
                    return 1;
                }
                file_array = tmp;

                // add file path to file_array
                file_array[index] = malloc(strlen(ent)+1);
                if(file_array[index] == NULL){
                    fprintf(stderr, "malloc: %s\n", strerror(errno));
                    free(ent);
                    for(int j = 0; j < index; j++)
                        free(file_array[j]);
                    free(file_array);
                    closedir(dp);
                    return 1;
                }
                len_ent = strlen(ent);
                memcpy(file_array[index], ent, len_ent);
                file_array[index++][len_ent] = '\0';
            }
        }
    }

    // sort files
    qsort(file_array, index, sizeof(char *), sort_alphabetically);

    // hash files and free file_array
    for(int j = 0; j < index; j++){
        hash_file(file_array[j]);
        free(file_array[j]);
    }

    closedir(dp);
    free(ent);
    free(file_array);
    return 0;
}

char* create_ent(char *ptr, char *path, char *name, int len)
{
    int length = len + strlen(name);
    char *tmp = realloc(ptr, length+2);
    if(tmp == NULL){
        fprintf(stderr, "realloc: %s\n", strerror(errno));
        free(ptr);
        return NULL;
    }
    ptr = tmp;
    memset(ptr, 0, length+2);

    strcat(ptr, path);
    strcat(ptr, "/");
    strcat(ptr, name);

    return ptr;
}

void hash_file(char *file)
{
    unsigned char *file_Hash = sha_256_file(file);
    if(file_Hash == NULL){
        printf("File hashing failed\n");
        return;
    }

    merkle_leaves = realloc(merkle_leaves, (count+1)*sizeof(leaves));
    memcpy(merkle_leaves[count].dir_name, file, strlen(file)+1);
    strToHexa(file_Hash, merkle_leaves[count].hash);
    count++;

    free(file_Hash);
}

static int sort_alphabetically(const void *l, const void *r)
{
    const char **str_a = (const char **)l;
    const char **str_b = (const char **)r;
    return strcasecmp(*str_a, *str_b);
}