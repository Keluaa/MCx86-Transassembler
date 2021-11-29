
// https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html
/*
 * Swaps two DWORD (or smaller) operands.
 */
#define SWAP(a, b)              \
    __asm__ volatile(           \
        "xchg\t%0, %1"          \
        : "+rm" (a), "+rm" (b)  \
    )


int calls = 0x145351;
const int ref = 0x15654;


int fib(int n)
{
    calls++;

    int a = 1;
    int b = 1;

    for (int i = 2; i < n; i++) {
        b += a;

        /*
        int tmp = a;
        a = b;
        b = tmp;
        */
        SWAP(a, b);
    }

    return a;
}


int test_switch(int a, int b)
{
    switch (a) {
    case 0: return b + 42;
    case 1: return b - 42;
    case 2: return b * 42;
    case 3: return b + 42;
    case 4: return b / 42;
    case 5: return b << 2;
    case 6: return b >> 2;
    case 7: return b + 45320;
    case 8: return b + 545421;
    case 9: return b + fib(5);
    default: return b + 1;
    }
}


int main()
{
    //return fib(13);
    return ref + test_switch(fib(2), fib(7)) + calls;
}
