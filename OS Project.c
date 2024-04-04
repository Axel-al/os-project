#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#define MAX_FILENAME_LENGTH 256
#define MAX_CONTENT_LENGTH 4096
#define MAX_METADATA_LENGTH 1024
#define MAX_PATH_LENGTH 1000

struct Metadata {
    mode_t permissions;
    uid_t owner;
    time_t mtime;
    off_t size;
};


void captureMetadata(const char *dir_path, FILE *snapshot_file) {
    DIR *dir = opendir(dir_path);
    if (dir == NULL) {
        perror("Error opening directory");
        exit(EXIT_FAILURE);
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            char full_path[MAX_PATH_LENGTH];
            snprintf(full_path, MAX_PATH_LENGTH, "%s/%s", dir_path, entry->d_name);

            struct stat file_stat;
            if (lstat(full_path, &file_stat) == -1) {
                perror("Error getting file stats");
                exit(EXIT_FAILURE);
            }

            if (strcmp(entry->d_name, "snapshot.txt") != 0) {
                struct Metadata metadata;
                metadata.permissions = file_stat.st_mode;
                metadata.owner = file_stat.st_uid;
                metadata.mtime = file_stat.st_mtime;
                metadata.size = file_stat.st_size;

                fprintf(snapshot_file, "%s - Permissions: %o, Owner: %d, Mtime: %ld, Size: %ld\n",
                        entry->d_name, metadata.permissions, metadata.owner, metadata.mtime, metadata.size);
            }
        }
    }

    closedir(dir);
}

typedef struct {
    char *Permissions;
    char *Owner;
    char *Mtime;
    char *Size;
} Metadata;

void parse_file(FILE *file, Metadata **parsed_data, int *num_files) {
    char content[MAX_CONTENT_LENGTH];
    fgets(content, MAX_CONTENT_LENGTH, file);
    char *line = strtok(content, "\n");
    *parsed_data = malloc(sizeof(Metadata) * MAX_METADATA_LENGTH);
    *num_files = 0;
    while ((line = strtok(NULL, "\n")) != NULL) {
        char *token = strtok(line, " - ");
        if (token == NULL)
            continue;
        char *filename = strdup(token);
        token = strtok(NULL, " - ");
        Metadata temp_metadata;
        while (token != NULL) {
            char *key = strtok(token, ": ");
            char *value = strtok(NULL, ": ");
            if (strcmp(key, "Permissions") == 0) {
                temp_metadata.Permissions = strdup(value);
            } else if (strcmp(key, "Owner") == 0) {
                temp_metadata.Owner = strdup(value);
            } else if (strcmp(key, "Mtime") == 0) {
                temp_metadata.Mtime = strdup(value);
            } else if (strcmp(key, "Size") == 0) {
                temp_metadata.Size = strdup(value);
            }
            token = strtok(NULL, ", ");
        }
        (*parsed_data)[*num_files] = temp_metadata;
        (*num_files)++;
    }
}

void compareMetadata(const char *dir_path, FILE *snapshot_file) {
    FILE *snapshot_file_copy = tmpfile();
    rewind(snapshot_file);
    char line[MAX_CONTENT_LENGTH];
    while (fgets(line, sizeof(line), snapshot_file) != NULL) {
        fputs(line, snapshot_file_copy);
    }
    rewind(snapshot_file_copy);

    Metadata *parse;
    int num_files;
    parse_file(snapshot_file_copy, &parse, &num_files);

    rewind(snapshot_file);
    rewind(snapshot_file_copy);

    struct dirent *entry;
    DIR *dp = opendir(dir_path);
    if (dp == NULL) {
        fprintf(stderr, "Cannot open directory %s\n", dir_path);
        exit(EXIT_FAILURE);
    }

    struct stat stats;
    while ((entry = readdir(dp)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strcmp(entry->d_name, "snapshot.txt") == 0) {
            continue;
        }

        char filepath[MAX_FILENAME_LENGTH];
        snprintf(filepath, sizeof(filepath), "%s/%s", dir_path, entry->d_name);

        if (stat(filepath, &stats) == -1) {
            perror("stat");
            exit(EXIT_FAILURE);
        }

        int i;
        for (i = 0; i < num_files; i++) {
            if (strcmp(entry->d_name, "snapshot.txt") != 0 && strcmp(entry->d_name, "snapshot.txt\n") != 0) {
                if (strcmp(entry->d_name, parse[i].Permissions) != 0) {
                    fprintf(snapshot_file, "File %s has been deleted.\n", entry->d_name);
                    break;
                }

                if (strcmp(entry->d_name, parse[i].Owner) != 0) {
                    fprintf(snapshot_file, "Owner of file %s has been changed.\n", entry->d_name);
                    break;
                }

                if (strcmp(entry->d_name, parse[i].Mtime) != 0 || strcmp(entry->d_name, parse[i].Size) != 0) {
                    fprintf(snapshot_file, "File %s has been modified.\n", entry->d_name);
                    break;
                }
            }
        }
    }

    closedir(dp);
    fclose(snapshot_file_copy);

    int i;
    for (i = 0; i < num_files; i++) {
        free(parse[i].Permissions);
        free(parse[i].Owner);
        free(parse[i].Mtime);
        free(parse[i].Size);
    }
    free(parse);
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <directory_path>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *dir_path = argv[1];
    char snapshot_path[MAX_PATH_LENGTH];
    snprintf(snapshot_path, MAX_PATH_LENGTH, "%s/snapshot.txt", dir_path);

    FILE *snapshot_file = fopen(snapshot_path, "r+");
    if (snapshot_file == NULL) {
        perror("Error opening snapshot file");
        exit(EXIT_FAILURE);
    }

    fseek(snapshot_file, 0, SEEK_END);
    if (ftell(snapshot_file) == 0) {
        fprintf(snapshot_file, "Snapshot for directory: %s\n", dir_path);
        fprintf(snapshot_file, "---------------------------------------\n");
        captureMetadata(dir_path, snapshot_file);
        printf("Initial snapshot captured.\n");
    } else {
        rewind(snapshot_file);
        compareMetadata(dir_path, snapshot_file);
    }

    fclose(snapshot_file);
    return EXIT_SUCCESS;
}