#include <stdio.h>
#include <dlfcn.h>

static void some_static_function(void) {
    dlopen("libfoo2.so", 0);
}

int main(int argc, char** argv) {
    // force to not inline some_static_function()
    void (*bar)(void) = NULL;
    if (argc) {
        bar = some_static_function;
    }
    dlopen("libfoo.so", 0);
    dlopen("libfoo3.so", 0);
    bar();
}
