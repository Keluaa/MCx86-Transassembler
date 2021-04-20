
/*
 * See this page for more info:
 * https://blogs.oracle.com/linux/hello-from-a-libc-free-world-part-1-v2
 *
 * And this post for the x86 assembly:
 * https://stackoverflow.com/a/2548601/8662187
 */


int main();


__attribute__((unused))
void _start() // NOLINT(bugprone-reserved-identifier)
{
    int ret = main();

    asm volatile(
        "movl $1, %%eax;" // Interrupt 1 is the exit function
        "movl %0, %%ebx;" // return value, passed as a parameter
        "int  $0x80;"     // syscall for x86
        "hlt;"            // protection to make sure any data after is not executed
        :
        : "m" (ret));
}
