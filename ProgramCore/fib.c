

int fib(int n)
{
    int a = 1;
    int b = 1;

    for (int i = 2; i < n; i++) {
        b += a;

        int tmp = a;
        a = b;
        b = tmp;
    }

    return a;
}


int main()
{
    return fib(13);
}
