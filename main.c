#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/*
 * Cross-platform dynamic-library loading.
 * On POSIX: dlopen / dlsym / dlclose  (link with -ldl)
 * On Windows: LoadLibraryA / GetProcAddress / FreeLibrary
 */
#ifdef _WIN32
#  include <windows.h>
#  define plugin_open(path)    ((void *)LoadLibraryA(path))
#  define plugin_sym(h, name)  ((void *)(uintptr_t)GetProcAddress((HMODULE)(h), (name)))
#  define plugin_close(h)      FreeLibrary((HMODULE)(h))
#else
#  include <dlfcn.h>
#  define plugin_open(path)    dlopen((path), RTLD_LAZY)
#  define plugin_sym(h, name)  dlsym((h), (name))
#  define plugin_close(h)      dlclose(h)
#endif

#define EXE_NAME	"my_sha1"
#define BLOCK_SIZE	4196

#define SHA1_HASH_SIZE  20

typedef int (*sha1_get_plugin_name_t)(char *name, int max_length);
typedef int (*sha1_init_t)(void);
typedef void (*sha1_update_t)(const uint8_t *data, uint32_t size);
typedef int (*sha1_get_t)(uint8_t *sha1_buffer);

int main(int argc, char* argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Syntax: " EXE_NAME ": <plugin> <input-file>\n");
        return 1;
    }

    void *plugin = plugin_open(argv[1]);
    if (!plugin) {
        fprintf(stderr, "Unable to load plugin: %s\n", argv[1]);
        return 2;
    }

    sha1_get_plugin_name_t sha1_get_plugin_name = (sha1_get_plugin_name_t) plugin_sym(plugin, "sha1_get_plugin_name");
    sha1_init_t sha1_init = (sha1_init_t) plugin_sym(plugin, "sha1_init");
    sha1_update_t sha1_update = (sha1_update_t) plugin_sym(plugin, "sha1_update");
    sha1_get_t sha1_get = (sha1_get_t) plugin_sym(plugin, "sha1_get");

    if (!sha1_get_plugin_name || !sha1_init || !sha1_update || !sha1_get) {
        fprintf(stderr, "Unable to find all the required symbols in the specified plugin dynamic library\n");
        plugin_close(plugin);
        return 3;
    }

    int init_result = sha1_init();
    if (init_result != 0) {
        fprintf(stderr, "Error %d in plugin initialisation!\n", init_result);
        plugin_close(plugin);
        return 4;
    }

    /* Open in binary mode: text mode on Windows translates \r\n and
     * would produce wrong SHA-1 digests for binary content.           */
    FILE *f = fopen(argv[2], "rb");
    if (!f) {
        perror("Unable to open input file");
        return 5;
    }

    uint8_t buffer[BLOCK_SIZE];
    size_t read_bytes;

    while (!feof(f)) {
        read_bytes = fread(buffer, 1, BLOCK_SIZE, f);
        sha1_update(buffer, (uint32_t)read_bytes);
    }

    uint8_t sha1_bytes[SHA1_HASH_SIZE];
    int result = sha1_get(sha1_bytes);

    if (result != 0) {
        fprintf(stderr, "Error %d in hash computation!\n", result);
        plugin_close(plugin);
        fclose(f);
        return 6;
    }

    for (int i = 0; i < SHA1_HASH_SIZE; i++)
        printf("%02x", sha1_bytes[i]);

    char plugin_name[256] = "?";
    sha1_get_plugin_name(plugin_name, sizeof(plugin_name));
    
    printf("\t%s\n", plugin_name);

    plugin_close(plugin);
    fclose(f);
    
    return 0;
}
