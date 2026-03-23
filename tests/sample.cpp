// Sample C++ file with various dangerous patterns for testing the filter.

#include <cstdlib>

struct Foo {
    int value;
};

// UAF: free then use
void uaf_example() {
    Foo* p = (Foo*)malloc(sizeof(Foo));
    p->value = 42;
    free(p);
    int x = p->value;  // use-after-free
}

// Safe: free in destructor (RAII)
class SafeOwner {
public:
    SafeOwner() : data_(malloc(100)) {}
    ~SafeOwner() {
        free(data_);  // should be excluded by destructor rule
    }
private:
    void* data_;
};

// Safe: null after free
void null_after_free() {
    char* buf = (char*)malloc(256);
    // ... use buf ...
    free(buf);
    buf = nullptr;  // should be excluded
}

// Dangerous: error path doesn't free
int error_path_leak(int flag) {
    int* arr = new int[100];
    if (flag < 0) {
        return -1;  // leak!
    }
    delete[] arr;
    return 0;
}

// Dangerous: double free potential
void maybe_double_free(bool cond) {
    void* ptr = malloc(64);
    if (cond) {
        free(ptr);
    }
    free(ptr);  // double free if cond was true
}
