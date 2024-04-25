#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <limits.h>

#define MAX_FILENAME_LENGTH 256
#define SEP "/"

typedef struct {
    char filename[MAX_FILENAME_LENGTH],
    permissions[6],
    owner[5],
    modify[26],
    size[26];
} Metadata;


Metadata* parse_file(FILE* file) {
    const int MAX_LINE_LENGTH = sizeof(Metadata) + 42;

    int sec_line_pos;
    int nb_line = -1;
    while(!feof(file)) {
        if (getc(file) == '\n') {
            nb_line++;
            if (nb_line == 1) sec_line_pos = ftell(file);
    }}
    fseek(file, sec_line_pos, SEEK_SET);

    if (nb_line < 1) nb_line = 1;
    Metadata* fileInfo = malloc(nb_line * sizeof(Metadata));
    char line[MAX_LINE_LENGTH];
    
    int count = 0;
    while (fgets(line, MAX_LINE_LENGTH, file)) {
        char* metadata = strrchr(line, '-');

        if (metadata == NULL || sscanf(metadata, "- Permissions: %5s, Owner: %4s, Modify: %[^,], Size: %[^\n]\n", 
            fileInfo[count].permissions, fileInfo[count].owner, fileInfo[count].modify, fileInfo[count].size) != 4) {
            
            printf("Error for line: %s", line);
            continue;
        }
        int filename_length = metadata - line - 1;
        strncpy(fileInfo[count].filename, line, filename_length);
        fileInfo[count++].filename[filename_length] = '\0';
    }
    
    fileInfo[count].filename[0] = '\0';
    return fileInfo;
}

void delete_element(Metadata* fileInfo, const int index) {
    for (int i = index; fileInfo[i].filename[0]!='\0'; i++) {
        strcpy(fileInfo[i].filename, fileInfo[i+1].filename);
        strcpy(fileInfo[i].permissions, fileInfo[i+1].permissions);
        strcpy(fileInfo[i].owner, fileInfo[i+1].owner);
        strcpy(fileInfo[i].modify, fileInfo[i+1].modify);
        strcpy(fileInfo[i].size, fileInfo[i+1].size);
    }
}

int compareMetadata(const char* dir_path, const int origin_path_length, FILE* output, const char* isolated_space) {
    FILE* snapshot_file;
    bool initialize = false;
    Metadata* parsed_file = malloc(1);
    parsed_file[0].filename[0] = '\0';

    char snapshot_path[strlen(dir_path)+14];
    strcpy(snapshot_path, dir_path);
    if (snapshot_path[strlen(dir_path)-1]!=SEP[0]) strcat(snapshot_path, SEP);
    strcat(snapshot_path, "snapshot.txt");
    
    if (access(snapshot_path, F_OK) == 0) {
        snapshot_file = fopen(snapshot_path, "r+");
    } else {
        initialize = true;
        snapshot_file = fopen(snapshot_path, "w+");
        printf("Directory %s is initialized...\n", dir_path);
    }
    if (snapshot_file == NULL) {
        printf("Error during the opening or the creation of the file in directory %s.\n", dir_path);
        return -1;
    }

    if (!initialize) {
        free(parsed_file);
        parsed_file = parse_file(snapshot_file);
        for (int i = 0; parsed_file[i].filename[0]!='\0'; i++) {
            char filename[MAX_FILENAME_LENGTH];
            strcpy(filename, parsed_file[i].filename);

            char type[10];
            if (S_ISDIR(atoi(parsed_file[i].permissions))) strcpy(type, "directory");
            else strcpy(type, "file");

            char path_file[strlen(dir_path)+strlen(filename)+2];
            strcpy(path_file, dir_path);
            if (path_file[strlen(dir_path)-1]!=SEP[0]) strcat(path_file, SEP);
            strcat(path_file, filename);
            

            if (access(path_file, F_OK) != 0) {
                printf("%c%s %s has been deleted.\n", toupper(type[0]), type+1, path_file+origin_path_length);
                delete_element(parsed_file, i--);
                continue;
            }

            struct stat stats;
            lstat(path_file, &stats);
            if (atoi(parsed_file[i].permissions) != stats.st_mode) {
                sprintf(parsed_file[i].permissions, "%d", stats.st_mode);
                printf("Permissions of %s %s have been modified.\n", type, path_file+origin_path_length);
            }
            if (atoi(parsed_file[i].owner) != stats.st_uid) {
                sprintf(parsed_file[i].owner, "%d", stats.st_uid);
                printf("Owner of %s %s has been changed.\n", type, path_file+origin_path_length);
            }
            if (atol(parsed_file[i].modify) != stats.st_mtime || atol(parsed_file[i].size) != stats.st_size) {
                sprintf(parsed_file[i].modify, "%ld", stats.st_mtime);
                sprintf(parsed_file[i].size, "%ld", stats.st_size);
                printf("%c%s %s has been modified.\n", toupper(type[0]), type+1, path_file+origin_path_length);
            }
        }
    }
    DIR* dir = opendir(dir_path);
    struct dirent* dir_entry;
    while((dir_entry = readdir(dir)) != NULL) {
        char* name = dir_entry->d_name;
        if (strcmp(name, "snapshot.txt") == 0 || strcmp(name, "..") == 0 || strcmp(name, ".") == 0) continue;

        char path_file[strlen(dir_path)+strlen(name)+2];
        strcpy(path_file, dir_path);
        if (path_file[strlen(dir_path)-1]!=SEP[0]) strcat(path_file, SEP);
        strcat(path_file, name);

        struct stat stats;
        lstat(path_file, &stats);
        if ((stats.st_mode & 0777) == 0) {
            int pid = fork();
            if (pid < 0) {
                printf("Error during the creation process for malicious verification.");
                return -1;
            } else if (pid == 0) {
                execl("./verify_for_malicious.sh", "verify_for_malicious.sh", path_file, (char *)NULL);
                exit(-1);
            } else {
                int status;
                waitpid(pid, &status, 0);
                int exit_status = WEXITSTATUS(status);
                if (exit_status == 255) {
                    printf("Error during the malicious verification.");
                    return -1;
                } else if (exit_status == 1) {
                    char moved_path_file[strlen(isolated_space)+strlen(path_file)+2];
                    strcpy(moved_path_file, isolated_space);
                    if (moved_path_file[strlen(moved_path_file)-1]!=SEP[0]) strcat(moved_path_file, SEP);
                    strcat(moved_path_file, path_file);
                    if (rename(path_file, moved_path_file) != 0) {
                        printf("Error during the move of file %s.", path_file);
                        return -1;
                    } 
                    continue;
                }
            }
        }

        if (S_ISDIR(stats.st_mode)) {
            if (!initialize) {
                char next_snapshot_path[strlen(path_file)+13];
                sprintf(next_snapshot_path, "%s%ssnapshot.txt", path_file, SEP);
                FILE* temp = fopen(next_snapshot_path, "a");
                fclose(temp);
            }
            compareMetadata(path_file, origin_path_length, output, isolated_space);
        }
        bool isFileSaved = false;
        int length = 1;
        for (int i = 0; parsed_file[i].filename[0] != '\0'; i++) {
            if (strcmp(parsed_file[i].filename, name) == 0) {
                isFileSaved = true;
            }
            length = i + 2;
        }
        if (!isFileSaved) {
            if (!initialize){
                char type[10];
                if (S_ISDIR(stats.st_mode)) strcpy(type, "Directory");
                else strcpy(type, "File");
                printf("%s %s has been created.\n", type, path_file+origin_path_length);
            }
            parsed_file = realloc(parsed_file, (length+1)*sizeof(Metadata));
            strcpy(parsed_file[length-1].filename, name);
            sprintf(parsed_file[length-1].permissions, "%d", stats.st_mode);
            sprintf(parsed_file[length-1].owner, "%d", stats.st_uid);
            sprintf(parsed_file[length-1].modify, "%ld", stats.st_mtime);
            sprintf(parsed_file[length-1].size, "%ld", stats.st_size);

            parsed_file[length].filename[0] = '\0';
        }
    }
    closedir(dir);

    rewind(snapshot_file);
    fprintf(snapshot_file, "Snapshot for directory: %s\n", dir_path);
    fprintf(snapshot_file, "---------------------------------------\n");
    for (int i = 0; parsed_file[i].filename[0] != '\0'; i++) {
        fprintf(snapshot_file, "%s - Permissions: %s, Owner: %s, Modify: %s, Size: %s\n", parsed_file[i].filename,
        parsed_file[i].permissions, parsed_file[i].owner, parsed_file[i].modify, parsed_file[i].size);
        
        if (output != NULL) {
            char abs_path[PATH_MAX+1];
            realpath(dir_path, abs_path);
            strcat(abs_path, SEP);
            strcat(abs_path, parsed_file[i].filename);
            fprintf(output, "%s - Permissions: %s, Owner: %s, Modify: %s, Size: %s\n", abs_path,
            parsed_file[i].permissions, parsed_file[i].owner, parsed_file[i].modify, parsed_file[i].size);
        }
    }
    free(parsed_file);
    fflush(snapshot_file);
    ftruncate(fileno(snapshot_file), ftell(snapshot_file));
    fclose(snapshot_file);
    return 0;
}

int main(int argc, char *argv[]) {
    int start = 1;
    int lpid[argc-1];
    if(argc >= 2) {
        FILE* output = NULL;
        char isolated_space[PATH_MAX+1];
        if (strcmp(argv[1], "-o") == 0) {
            switch (argc) {
            case 2:
                printf("No output specified.\n");
                return -1;

            case 3:
                printf("No input specified.\n");
                return -1;
            }
            start = 3;
            output = fopen(argv[2], "w");
            if (strcmp(argv[3], "-s") == 0) {
                switch (argc) {
                case 4:
                    printf("No isolated space specified.\n");
                    return -1;
                
                case 5:
                    printf("No input specified.\n");
                    return -1;
                }
                start = 5;
                strcpy(isolated_space, argv[4]);
            }
        } else if (strcmp(argv[1], "-s") == 0) {
            switch (argc) {
            case 2:
                printf("No isolated space specified.\n");
                return -1;

            case 3:
                printf("No input specified.\n");
                return -1;
            }
            start = 3;
            strcpy(isolated_space, argv[2]);
            if (strcmp(argv[3], "-o") == 0) {
                switch (argc) {
                case 4:
                    printf("No output specified.\n");
                    return -1;
                
                case 5:
                    printf("No input specified.\n");
                    return -1;
                }
                start = 5;
                output = fopen(argv[4], "w");
            }
        }
        for (int i = start; i < argc; i++) {
            int pid = fork();
            lpid[i - start] = pid;
            if (pid < 0) {
                printf("Error in the opening of the process for %s.\n", argv[i]);
                return -1;
            } else if (pid == 0) {
                int length;
                if (argv[1][strlen(argv[i]-1)] == SEP[0]) length = strlen(argv[i]);
                else length = strlen(argv[i]) + 1;
                int error;
                if ((error = compareMetadata(argv[i], length, output, isolated_space)) != 0) {
                    printf("Error during the creation of snapshot for directory %s.\n", argv[i]);
                    exit(error);
                } else {
                    printf("Snapshot for directory %s created succesfully.\n", argv[i]);
                    exit(0);
                }
            }
        }
        if (output != NULL) fclose(output);
    } else {
        printf("No argument has been used.\n");
        return -1;
    }
    for (int i = 0; i < argc - start; i++) {
        int status;
        int wpid = waitpid(lpid[i], &status, 0);
        int exit_code = WEXITSTATUS(status);
        if (exit_code > 127) exit_code -= 256;
        printf("Child Process %d terminated with PID %d and exit code %d.\n", i+1, wpid, exit_code);
    }

    return 0;
}
